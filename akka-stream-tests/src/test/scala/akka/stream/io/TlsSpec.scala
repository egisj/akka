package akka.stream.io

import java.security.{ KeyStore, SecureRandom }
import javax.net.ssl.{ TrustManagerFactory, KeyManagerFactory, SSLContext }
import akka.stream.{ Graph, BidiShape, ActorFlowMaterializer }
import akka.stream.scaladsl._
import akka.stream.ssl._
import akka.stream.testkit.{ TestUtils, AkkaSpec }
import akka.util.ByteString
import scala.concurrent.Await
import scala.concurrent.duration._
import scala.collection.immutable
import scala.util.Random
import akka.stream.stage.AsyncStage
import akka.stream.stage.AsyncContext
import java.util.concurrent.TimeoutException
import akka.actor.ActorSystem
import javax.net.ssl.SSLSession
import akka.pattern.{ after ⇒ later }
import scala.concurrent.Future
import java.net.InetSocketAddress

object TlsSpec {

  val rnd = new Random

  def initSslContext(): SSLContext = {

    val password = "changeme"

    val keyStore = KeyStore.getInstance(KeyStore.getDefaultType)
    keyStore.load(getClass.getResourceAsStream("/keystore"), password.toCharArray)

    val trustStore = KeyStore.getInstance(KeyStore.getDefaultType)
    trustStore.load(getClass.getResourceAsStream("/truststore"), password.toCharArray)

    val keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm)
    keyManagerFactory.init(keyStore, password.toCharArray)

    val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm)
    trustManagerFactory.init(trustStore)

    val context = SSLContext.getInstance("TLS")
    context.init(keyManagerFactory.getKeyManagers, trustManagerFactory.getTrustManagers, new SecureRandom)
    context
  }

  class Timeout()(implicit system: ActorSystem) extends AsyncStage[ByteString, ByteString, Unit] {
    private var last: ByteString = _

    override def initAsyncInput(ctx: AsyncContext[ByteString, Unit]) = {
      val cb = ctx.getAsyncCallback()
      system.scheduler.scheduleOnce(2.seconds)(cb.invoke(()))(system.dispatcher)
    }

    override def onAsyncInput(u: Unit, ctx: AsyncContext[ByteString, Unit]) =
      ctx.fail(new TimeoutException(s"timeout expired, last element was $last"))

    override def onPush(elem: ByteString, ctx: AsyncContext[ByteString, Unit]) = {
      last = elem
      if (ctx.isHoldingDownstream) ctx.pushAndPull(elem)
      else ctx.holdUpstream()
    }

    override def onPull(ctx: AsyncContext[ByteString, Unit]) =
      if (ctx.isFinishing) ctx.pushAndFinish(last)
      else if (ctx.isHoldingUpstream) ctx.pushAndPull(last)
      else ctx.holdDownstream()

    override def onUpstreamFinish(ctx: AsyncContext[ByteString, Unit]) =
      if (ctx.isHoldingUpstream) ctx.absorbTermination()
      else ctx.finish()
  }
}

class TlsSpec extends AkkaSpec("akka.loglevel=INFO\nakka.actor.debug.receive=off") {
  import TlsSpec._

  import system.dispatcher
  implicit val materializer = ActorFlowMaterializer()

  import FlowGraph.Implicits._

  "StreamTLS" must {
    import StreamTls._

    // All of these are reusable
    val sslContext = initSslContext()

    val debug = Flow[SslTlsInbound].map { x ⇒
      x match {
        case SessionTruncated   ⇒ system.log.debug(s" ----------- truncated ")
        case SessionBytes(_, b) ⇒ system.log.debug(s" ----------- (${b.size}) ${b.take(32).utf8String}")
      }
      x
    }

    val cipherSuites = NegotiateNewSession.withCipherSuites("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_128_CBC_SHA")
    def clientTls(closing: Closing) = StreamTls(sslContext, cipherSuites, Client, closing)
    def serverTls(closing: Closing) = StreamTls(sslContext, cipherSuites, Server, closing)

    trait Named {
      def name: String = getClass.getName.reverse.dropWhile(c ⇒ "$0123456789".indexOf(c) != -1).takeWhile(_ != '$').reverse
    }

    trait CommunicationSetup extends Named {
      def flow(leftClosing: Closing, rightClosing: Closing, flow: Flow[SslTlsInbound, SslTlsOutbound, Any]): Flow[SslTlsOutbound, SslTlsInbound, Any]
    }

    object ClientInitiates extends CommunicationSetup {
      def flow(leftClosing: Closing, rightClosing: Closing, flow: Flow[SslTlsInbound, SslTlsOutbound, Any]) =
        clientTls(leftClosing) atop serverTls(rightClosing).reversed join flow
    }

    object ServerInitiates extends CommunicationSetup {
      def flow(leftClosing: Closing, rightClosing: Closing, flow: Flow[SslTlsInbound, SslTlsOutbound, Any]) =
        serverTls(leftClosing) atop clientTls(rightClosing).reversed join flow
    }

    def server(flow: Flow[ByteString, ByteString, Any]): InetSocketAddress = {
      val server = StreamTcp()
        .bind(new InetSocketAddress("localhost", 0))
        .to(Sink.foreach(c ⇒ c.flow.join(flow).run()))
        .run()
      Await.result(server, 2.seconds).localAddress
    }

    object ClientInitiatesViaTcp extends CommunicationSetup {
      def flow(leftClosing: Closing, rightClosing: Closing, flow: Flow[SslTlsInbound, SslTlsOutbound, Any]) = {
        val local = server(serverTls(rightClosing).reversed join flow)
        clientTls(leftClosing) join StreamTcp().outgoingConnection(local)
      }
    }

    object ServerInitiatesViaTcp extends CommunicationSetup {
      def flow(leftClosing: Closing, rightClosing: Closing, flow: Flow[SslTlsInbound, SslTlsOutbound, Any]) = {
        val local = server(clientTls(rightClosing).reversed join flow)
        serverTls(leftClosing) join StreamTcp().outgoingConnection(local)
      }
    }

    val communicationPatterns =
      Seq(
        ClientInitiates,
        ServerInitiates,
        ClientInitiatesViaTcp,
        ServerInitiatesViaTcp)

    trait PayloadScenario extends Named {
      def flow: Flow[SslTlsInbound, SslTlsOutbound, Any] =
        Flow[SslTlsInbound]
          .map {
            var session: SSLSession = null
            def setSession(s: SSLSession) = {
              session = s
              system.log.debug(s"new session: $session (${session.getId mkString ","})")
            }

            {
              case SessionTruncated ⇒ SendBytes(ByteString("TRUNCATED"))
              case SessionBytes(s, b) if session == null ⇒
                setSession(s)
                SendBytes(b)
              case SessionBytes(s, b) if s != session ⇒
                setSession(s)
                SendBytes(ByteString("NEWSESSION") ++ b)
              case SessionBytes(s, b) ⇒ SendBytes(b)
            }
          }
      def leftClosing: Closing = IgnoreComplete
      def rightClosing: Closing = IgnoreComplete

      def inputs: immutable.Seq[SslTlsOutbound]
      def output: ByteString

      protected def send(str: String) = SendBytes(ByteString(str))
      protected def send(ch: Char) = SendBytes(ByteString(ch.toByte))
    }

    object SingleBytes extends PayloadScenario {
      val str = "0123456789"
      def inputs = str.map(ch ⇒ SendBytes(ByteString(ch.toByte)))
      def output = ByteString(str)
    }

    object MediumMessages extends PayloadScenario {
      val strs = "0123456789" map (d ⇒ d.toString * (rnd.nextInt(9000) + 1000))
      def inputs = strs map (s ⇒ SendBytes(ByteString(s)))
      def output = ByteString((strs :\ "")(_ ++ _))
    }

    object LargeMessages extends PayloadScenario {
      // TLS max packet size is 16384 bytes
      val strs = "0123456789" map (d ⇒ d.toString * (rnd.nextInt(9000) + 17000))
      def inputs = strs map (s ⇒ SendBytes(ByteString(s)))
      def output = ByteString((strs :\ "")(_ ++ _))
    }

    object EmptyBytesFirst extends PayloadScenario {
      def inputs = List(ByteString.empty, ByteString("hello")).map(SendBytes)
      def output = ByteString("hello")
    }

    object EmptyBytesInTheMiddle extends PayloadScenario {
      def inputs = List(ByteString("hello"), ByteString.empty, ByteString(" world")).map(SendBytes)
      def output = ByteString("hello world")
    }

    object EmptyBytesLast extends PayloadScenario {
      def inputs = List(ByteString("hello"), ByteString.empty).map(SendBytes)
      def output = ByteString("hello")
    }

    object ImpatientRHS extends PayloadScenario {
      override def flow =
        Flow[SslTlsInbound]
          .mapConcat {
            case SessionTruncated       ⇒ SessionTruncated :: Nil
            case SessionBytes(s, bytes) ⇒ bytes.map(b ⇒ SessionBytes(s, ByteString(b)))
          }
          .take(5)
          .mapAsync(10, x ⇒ later(500.millis, system.scheduler)(Future.successful(x)))
          .via(super.flow)
      override def rightClosing = IgnoreCancel

      val str = "abcdef" * 100
      def inputs = str.map(send)
      def output = ByteString(str.take(5))
    }

    object SessionRenegotiationBySender extends PayloadScenario {
      def inputs = List(send("hello"), NegotiateNewSession.default, send("world"))
      def output = ByteString("helloNEWSESSIONworld")
    }

    // difference is that the RHS engine will now receive the handshake while trying to send
    object SessionRenegotiationByReceiver extends PayloadScenario {
      val str = "abcdef" * 100
      def inputs = str.map(send) ++ Seq(NegotiateNewSession.default) ++ "hello world".map(send)
      def output = ByteString(str + "NEWSESSIONhello world")
    }

    val logCipherSuite = Flow[SslTlsInbound]
      .map {
        var session: SSLSession = null
        def setSession(s: SSLSession) = {
          session = s
          system.log.debug(s"new session: $session (${session.getId mkString ","})")
        }

        {
          case SessionTruncated ⇒ SendBytes(ByteString("TRUNCATED"))
          case SessionBytes(s, b) if s != session ⇒
            setSession(s)
            SendBytes(ByteString(s.getCipherSuite) ++ b)
          case SessionBytes(s, b) ⇒ SendBytes(b)
        }
      }

    object SessionRenegotiationFirstOne extends PayloadScenario {
      override def flow = logCipherSuite
      def inputs = NegotiateNewSession.withCipherSuites("TLS_RSA_WITH_AES_128_CBC_SHA") :: send("hello") :: Nil
      def output = ByteString("TLS_RSA_WITH_AES_128_CBC_SHAhello")
    }

    object SessionRenegotiationFirstTwo extends PayloadScenario {
      override def flow = logCipherSuite
      def inputs = NegotiateNewSession.withCipherSuites("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA") :: send("hello") :: Nil
      def output = ByteString("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHAhello")
    }

    val scenarios =
      Seq(
        SingleBytes,
        MediumMessages,
        LargeMessages,
        EmptyBytesFirst,
        EmptyBytesInTheMiddle,
        EmptyBytesLast,
        ImpatientRHS,
        SessionRenegotiationBySender,
        SessionRenegotiationByReceiver,
        SessionRenegotiationFirstOne,
        SessionRenegotiationFirstTwo)

    for {
      commPattern ← communicationPatterns
      scenario ← scenarios
    } {
      s"work in mode ${commPattern.name} while sending ${scenario.name}" in {
        val onRHS = debug.via(scenario.flow)
        val f =
          Source(scenario.inputs)
            .via(commPattern.flow(scenario.leftClosing, scenario.rightClosing, onRHS))
            .via(debug)
            .collect { case SessionBytes(_, b) ⇒ b }
            .scan(ByteString.empty)(_ ++ _)
            .transform(() ⇒ new Timeout)
            .dropWhile(_.size < scenario.output.size)
            .runWith(Sink.head)

        Await.result(f, 3.seconds).utf8String should be(scenario.output.utf8String)
      }
    }

  }

  // TODO: Add parallel
  // TODO: Add chained parallel, loopback
  // TODO: Add inverted chains (client-server-server-client and client-server-client-server and server-client-client-server)
  // TODO: Add no bytes, short bytes, long stream, large bytes
}
