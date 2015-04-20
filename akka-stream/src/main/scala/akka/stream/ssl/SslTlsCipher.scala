/**
 * Copyright (C) 2009-2014 Typesafe Inc. <http://www.typesafe.com>
 */
package akka.stream.ssl

import scala.collection.immutable
import akka.util.ByteString
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSession
import scala.annotation.varargs

sealed trait SslTlsInbound
case object SessionTruncated extends SslTlsInbound
case class SessionBytes(session: SSLSession, bytes: ByteString) extends SslTlsInbound {
  lazy val localCertificates = Option(session.getLocalCertificates).map(_.toList).getOrElse(Nil)
  lazy val localPrincipal = Option(session.getLocalPrincipal)
  lazy val peerCertificates =
    try Option(session.getPeerCertificates).map(_.toList).getOrElse(Nil)
    catch { case e: SSLPeerUnverifiedException ⇒ Nil }
  lazy val peerPrincipal =
    try Option(session.getPeerPrincipal)
    catch { case e: SSLPeerUnverifiedException ⇒ None }
}

sealed trait SslTlsOutbound

case class NegotiateNewSession(
  enabledCipherSuites: Option[immutable.Seq[String]],
  enabledProtocols: Option[immutable.Seq[String]],
  clientAuth: Option[ClientAuth],
  sslParameters: Option[SSLParameters]) extends SslTlsOutbound

object NegotiateNewSession {
  val default = NegotiateNewSession(None, None, None, None)

  @varargs
  def withCipherSuites(s: String*) = default.copy(enabledCipherSuites = Some(s.toList))

  @varargs
  def withProtocols(p: String*) = default.copy(enabledProtocols = Some(p.toList))

  def withClientAuth(ca: ClientAuth) = default.copy(clientAuth = Some(ca))

  def withParameters(p: SSLParameters) = default.copy(sslParameters = Some(p))
}

case class SendBytes(bytes: ByteString) extends SslTlsOutbound

sealed abstract class ClientAuth
object ClientAuth {
  case object None extends ClientAuth
  case object Want extends ClientAuth
  case object Need extends ClientAuth

  def none: ClientAuth = None
  def want: ClientAuth = Want
  def need: ClientAuth = Need
}
