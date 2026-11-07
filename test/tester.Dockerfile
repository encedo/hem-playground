# PHP for hem-api-tester (fw-1.3.x needs bcmath; sodium and openssl are in the base image)
FROM php:8.4-cli
RUN docker-php-ext-install bcmath >/dev/null
