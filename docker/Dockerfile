FROM php:8.0-cli-alpine

RUN set -xe \
    && apk add --no-cache gmp \
    # Install dependencies
    && apk add --no-cache --virtual .build-deps \
        $PHPIZE_DEPS \
        gmp-dev \
    # Install php extensions
    && docker-php-ext-install -j $(nproc) \
        opcache \
        gmp \
    # Remove dependencies after install
    && apk del --no-cache -f .build-deps \
    && rm -rf /tmp/pear

COPY --from=composer /usr/bin/composer /usr/bin/composer

ARG USER_ID
ARG GROUP_ID

RUN set -xe \
    && apk add --no-cache shadow \
    && usermod --uid ${USER_ID:-1000} www-data \
    && groupmod --gid ${GROUP_ID:-1000} www-data \
    && apk del --no-cache shadow \
    && mkdir -p /srv/app \
    && chown www-data:www-data /srv/app \
    && chmod 755 /srv/app

ENV PS1='\[\033[1;36m\][\u@\h] \[\033[1;34m\]\w\[\033[0;35m\] \[\033[1;36m\]\$ \[\033[0m\]'

WORKDIR /srv/app
USER www-data

CMD ["php", "-a"]
