package ru.projektio.apigateway.config

import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.stereotype.Component

@Component
@EnableConfigurationProperties(JwtProperties::class)
class PropertiesConfig