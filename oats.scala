/**
 * A simple OAuth proxy.
 *
 * Usage: scala oats [LOCAL_PORT] [DESTINATION_HOST] [OAUTH_KEY] [OAUTH_SECRET]
 *
 */

import java.io._
import java.net._
import java.security.GeneralSecurityException
import java.util.Random

import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

import scala.annotation.tailrec
import scala.collection._
import scala.collection.mutable.ArrayBuffer

/** Various HTTP protocol related utilities */
object HTTPUtils {
  def base64Encode(bytes: Array[Byte]) = javax.xml.bind.DatatypeConverter.printBase64Binary(bytes)

  def urlEncode(s: String): String = URLEncoder.encode(s, "UTF-8")

  def urlEncode(url: String, params: Map[String, String]): String = {
    val queryDelim = if (url contains "?") "&" else "?"
    val sb = new StringBuilder(url + queryDelim)
    var first = true
    for ((k, v) <- params.toSeq.sorted) {
      if (!first) sb.append("&")
      sb.append(urlEncode(k) + "=" + urlEncode(v))
      first = false
    }
    sb.toString
  }

  def headerEncode(name: String, params: Map[String, String]): String = {
    name + " " + (params map { case (k, v) => k + "=\"" + urlEncode(v) + "\"" } mkString ", ")
  }

  /** Split a string in two parts at first `delim` character */
  def split(s: String, delim: Char) = {
    val pos = s.indexOf(delim)
    if (pos == -1) s -> ""
    else s.substring(0, pos) -> s.substring(pos+1, s.length)
  }

  /** Split header string "Accept: application/json" -> ("Accept", "application/json") */
  def splitHeader(s: String, delim: Char) = {
    val pos = s.indexOf(delim)
    if (pos == -1) s -> ""
    else s.substring(0, pos) -> s.substring(pos+2, s.length)
  }

}

import HTTPUtils._

/** Sign URLs with OAuth version 1 signature */
class OAuthSign(key: String, secret: String) {

  private val random = new Random(System.nanoTime)

  protected def newOAuthParams = Map(
    "oauth_consumer_key"     -> key,
    "oauth_version"          -> "1.0",
    "oauth_signature_method" -> "HMAC-SHA1",
    "oauth_timestamp"        -> timestamp,
    "oauth_nonce"            -> nonce
  )

  def header(method: String, requestUrl: String, params: Map[String, String]) = {
    val oauth = newOAuthParams
    headerEncode("OAuth", oauth + signatureParam(method, requestUrl, params ++ oauth))
  }

  def sign(method: String, requestUrl: String, params: Map[String, String]) = {
    val oauth = newOAuthParams
    urlEncode(requestUrl, params ++ oauth + signatureParam(method, requestUrl, params ++ oauth))
  }

  protected def signatureParam(method: String, requestUrl: String, params: Map[String, String]) = {
    "oauth_signature" -> signature(method, requestUrl, params)
  }

  protected def signature(method: String, requestUrl: String, requestParams: Map[String, String]) = {
    def canonicalize(method: String, url: String, params: Map[String, String]) = {
      val sb = new StringBuilder()
      sb.append(method)
      sb.append("&")
      sb.append(urlEncode(url))
      sb.append("&")
      sb.append(urlEncode(params.toSeq.sorted map { case (k, v) => k + "=" + v } mkString "&"))
      sb.toString
    }
    val base = canonicalize(method, requestUrl, requestParams)
    val keyString = urlEncode(secret)  + "&"
    val key = new SecretKeySpec(keyString.getBytes("UTF-8"), "HmacSHA1")
    val mac = Mac.getInstance("HmacSHA1")
    mac.init(key)
    base64Encode(mac.doFinal(base.getBytes("UTF-8"))).trim()
  }

  protected def timestamp = (System.currentTimeMillis / 1000L).toString

  protected def nonce = math.abs(random.nextLong).toString
}

/** A simple OAuth proxy; listens on `port` for HTTP requests and forwards
 *  signed requests to `host`.
 */
class Oats(
  val port: Int,
  val host: String,
  val sign: OAuthSign,
  val https: Boolean,
  val oauthHeader: Boolean
) {
  private val HTTPRequest = """([^ ]+) (\/.*) HTTP.*""".r

  val socket = new ServerSocket(port)
  println("OAuth proxy running on port %d / forwarding to %s" format (port, host))

  // main application loop; process one request at a time.
  while (true) {
    println("Waiting for request...")
    val client = socket.accept()
    val in = new BufferedReader(new InputStreamReader(client.getInputStream()))
    val output = new DataOutputStream(client.getOutputStream())

    try {
      val request = in.readLine()
      println("request: %s" format request)

      val Seq(method, fullpath) = HTTPRequest.unapplySeq(request).get
      println("method: %s" format method)
      println("fullpath: %s" format fullpath)

      val (path, params): (String, Map[String, String]) =
        if (!fullpath.contains("?"))
          (fullpath -> Map.empty)
        else {
          val (path, params) = split(fullpath, '?')
          val paramsMap: Map[String, String] = (params split '&') map { split(_, '=') } toMap;
          path -> paramsMap
        }
      println("path: %s" format path)
      println("params:\n%s\n" format (params mkString "\n"))

      var headers = {
        @tailrec def read(headers: Map[String, String] = Map.empty): Map[String, String] = {
          val header = in.readLine()
          if (header != null && header != "") read(headers + splitHeader(header, ':'))
          else headers
        }
        mutable.Map() ++ read()
      }
      println("headers:\n%s\n" format (headers mkString "\n"))

      val contentLength = headers.get("Content-Length") map (_.toLong)
      val body = contentLength map { len =>
        val buf = new ArrayBuffer[Byte](16 * 1024)
        @tailrec def read() {
          if (buf.size < len) {
            val next = in.read()
            if (next != -1) {
              buf += next.toByte
              read()
            }
          }
        }
        read()
        buf.toArray
      }
      if (body.isDefined) {
        println("body:\n%s\n" format (new String(body.get)))
      }

      val url = if (!oauthHeader) {
        val signed = oauth.sign(method, (if (https) "https://" else "http://") + host + path, params)
        println("signed: " + signed)
        signed
      } else {
        val line = oauth.header(method, (if (https) "https://" else "http://") + host + path, params)
        headers("Authorization") = line
        urlEncode((if (https) "https://" else "http://") + host + path, params)
      }

      headers("Host") = host

      println("Headers:\n%s\n" format (headers mkString "\n"))

      val response = http(method, url, headers, body)
      println("Response:")
      println(response)

      output.writeBytes(response)
    } catch {
      case e: Exception => e.printStackTrace()
    } finally {
      output.close()
      client.close()
    }
  }

  /** Perform HTTP request */
  def http(method: String, url: String, headers: Map[String, String], body: Option[Array[Byte]]) = {
    val result = new StringBuilder()
    val conn = new URL(url).openConnection().asInstanceOf[HttpURLConnection]
    try {
      conn.setInstanceFollowRedirects(true)
      HttpURLConnection.setFollowRedirects(true)
      conn.setRequestMethod(method)
      for ((k, v) <- headers) {
        conn.setRequestProperty(k, v)
      }
      if (body.isDefined) {
        conn.setDoOutput(true)
        conn.getOutputStream.write(body.get)
      }
      try {
        val in = new BufferedReader(new InputStreamReader(conn.getInputStream()))
        try {
          var line = in.readLine()
          while (line != null) {
            result.append(line)
            line = in.readLine()
          }
        } finally {
          in.close()
        }
      } catch {
        case e: IOException if (conn.getErrorStream != null) =>
          val in = new BufferedReader(new InputStreamReader(conn.getErrorStream))
          try {
            var line = in.readLine()
            while (line != null) {
              result.append(line)
              line = in.readLine()
            }
          } finally {
            in.close()
          }
      }
    } finally {
      conn.disconnect()
    }
    result.toString
 }
}

// command-line parsing
if (args.size != 3) {
  println("Usage:  scala oats [DESTINATION_HOST] [OAUTH_KEY] [OAUTH_SECRET]")
  println()
  println("Optional parameters:")
  println()
  println("  -Dport=8081           #  Local port to listen")
  println("  -Dhttps=true          #  Set to true if using HTTPS")
  println("  -Doauth.header=true   #  Pass OAuth authorization header instead of URL params")
  println()
  System.exit(1)
}

val https  = System.getProperty("https", "false").equalsIgnoreCase("true")
val header = System.getProperty("oauth.header", "false").equalsIgnoreCase("true")
val port   = System.getProperty("port", "8081").toInt
val host   = args(0)
val key    = args(1)
val secret = args(2)

// application kickoff
val oauth = new OAuthSign(key, secret)
new Oats(port, host, oauth, https, header)

