# PHP for hem-api-tester (FW 1.3 tests need bcmath; sodium and openssl are in the base image)
FROM php:8.4-cli
RUN docker-php-ext-install bcmath >/dev/null
