package ru.projektio.apigateway.filters

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import org.springframework.beans.factory.annotation.Value
import org.springframework.cloud.gateway.filter.GatewayFilter
import org.springframework.http.HttpHeaders
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.stereotype.Component
import java.security.*
import java.security.spec.*
import java.util.*

@Value("\${jwt.publicRsaFile}")
private lateinit var publicKeyStr: String

@Component
class JwtHeaderFilter : AbstractGatewayFilterFactory<JwtHeaderFilter.Config>(Config::class.java) {
    class Config

    override fun apply(config: Config): GatewayFilter {
        return GatewayFilter { exchange, chain ->
            val request = exchange.request
            val headers = request.headers

            val authHeader = headers.getFirst(HttpHeaders.AUTHORIZATION)
            if (authHeader.isNullOrEmpty()) {
                throw IllegalArgumentException("Authorization header is missing")
            }

            if (!authHeader.startsWith("Bearer ")) {
                throw IllegalArgumentException("Invalid Authorization header format. Expected 'Bearer <token>'")
            }

            val jwt = authHeader.substring(7)
            if (jwt.isBlank()) {
                throw IllegalArgumentException("JWT token is empty")
            }

            val claims: Claims = try {
                Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(jwt)
                    .payload
            } catch (ex: Exception) {
                throw IllegalArgumentException("Invalid JWT: ${ex.message}")
            }

            val userId = claims.subject ?: claims.get("user_id", String::class.java)
            if (userId.isNullOrEmpty()) {
                throw IllegalArgumentException("user_id not found in JWT")
            }

            val modifiedRequest: ServerHttpRequest = request.mutate()
                .header("X-User-ID", userId)
                .build()

            chain.filter(exchange.mutate().request(modifiedRequest).build())
        }
    }

    companion object {
        private val publicKey: PublicKey by lazy {
            KeyFactory.getInstance("RSA")
                .generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyStr)))
        }
    }
}