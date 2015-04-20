package akka.stream.ssl

import akka.stream.impl.StreamLayout.Module
import akka.stream._
import akka.stream.ssl._
import akka.util.ByteString
import javax.net.ssl.SSLContext

object StreamTls {
  sealed trait Role
  case object Client extends Role
  case object Server extends Role

  sealed trait Closing {
    def ignoreCancel: Boolean
    def ignoreComplete: Boolean
  }
  case object EagerClose extends Closing {
    override def ignoreCancel = false
    override def ignoreComplete = false
  }
  case object IgnoreCancel extends Closing {
    override def ignoreCancel = true
    override def ignoreComplete = false
  }
  case object IgnoreComplete extends Closing {
    override def ignoreCancel = false
    override def ignoreComplete = true
  }
  case object IgnoreBoth extends Closing {
    override def ignoreCancel = true
    override def ignoreComplete = true
  }

  /**
   * Scala API: create a StreamTls [[BidiFlow]].
   */
  def apply(sslContext: SSLContext, firstSession: NegotiateNewSession,
            role: Role, closing: Closing = IgnoreComplete): scaladsl.BidiFlow[SslTlsOutbound, ByteString, ByteString, SslTlsInbound, Unit] =
    new scaladsl.BidiFlow(TlsModule(OperationAttributes.none, sslContext, firstSession, role, closing))

  /**
   * Java API: create a StreamTls [[BidiFlow]] in client mode.
   */
  def client(sslContext: SSLContext, firstSession: NegotiateNewSession): javadsl.BidiFlow[SslTlsOutbound, ByteString, ByteString, SslTlsInbound, Unit] =
    new javadsl.BidiFlow(apply(sslContext, firstSession, Client))

  /**
   * Java API: create a StreamTls [[BidiFlow]] in server mode.
   */
  def server(sslContext: SSLContext, firstSession: NegotiateNewSession): javadsl.BidiFlow[SslTlsOutbound, ByteString, ByteString, SslTlsInbound, Unit] =
    new javadsl.BidiFlow(apply(sslContext, firstSession, Server))

  case class TlsModule(plainIn: Inlet[SslTlsOutbound], plainOut: Outlet[SslTlsInbound],
                       cipherIn: Inlet[ByteString], cipherOut: Outlet[ByteString],
                       shape: Shape, attributes: OperationAttributes,
                       sslContext: SSLContext, firstSession: NegotiateNewSession,
                       role: Role, closing: Closing) extends Module {
    override def subModules: Set[Module] = Set.empty

    override def withAttributes(att: OperationAttributes): Module = copy(attributes = att)
    override def carbonCopy: Module = {
      val mod = TlsModule(attributes, sslContext, firstSession, role, closing)
      if (plainIn == shape.inlets(0)) mod
      else mod.replaceShape(mod.shape.asInstanceOf[BidiShape[_, _, _, _]].reversed)
    }

    override def replaceShape(s: Shape) =
      if (s == shape) this
      else if (shape.hasSamePortsAs(s)) copy(shape = s)
      else throw new IllegalArgumentException("trying to replace shape with different ports")
  }

  object TlsModule {
    def apply(attributes: OperationAttributes, sslContext: SSLContext, firstSession: NegotiateNewSession, role: Role, closing: Closing): TlsModule = {
      val name = attributes.nameOrDefault(s"StreamTls($role)")
      val cipherIn = new Inlet[ByteString](s"$name.cipherIn")
      val cipherOut = new Outlet[ByteString](s"$name.cipherOut")
      val plainIn = new Inlet[SslTlsOutbound](s"$name.transportIn")
      val plainOut = new Outlet[SslTlsInbound](s"$name.transportOut")
      val shape = new BidiShape(plainIn, cipherOut, cipherIn, plainOut)
      TlsModule(plainIn, plainOut, cipherIn, cipherOut, shape, attributes, sslContext, firstSession, role, closing)
    }
  }
}
