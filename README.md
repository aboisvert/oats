A simple Scala command-line OAuth proxy.
=============================================================

(Currently only supports OAuth version 1.0 URL signing)

### Usage ###

    scala oats.scala LOCAL_PORT DESTINATION_HOST OAUTH_KEY OAUTH_SECRET

e.g.,

    scala oats.scala 8081 api.example.com k1234567890 dd50701259518fddb730

### Target platform ###

* Scala 2.9.0+
* JVM 1.5+

### License ###

Oats is is licensed under the terms of the Apache Software License v2.0.
<http://www.apache.org/licenses/LICENSE-2.0.html>
