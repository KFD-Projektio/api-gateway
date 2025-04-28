package ru.projektio.apigateway.exception

class JwtAuthenticationException(
    message: String,
    cause: Throwable? = null
) : RuntimeException(message, cause)