#!/bin/bash

rm -rf composer.phar
wget https://github.com/composer/composer/releases/latest/download/composer.phar -O composer.phar
php composer.phar install -vvv
while true
counter=1
do
  if curl mysql:3306 2>&1 | grep -qs "Received HTTP/0.9 when not allowed"; then
    echo "Continue to lotusboard setup"
    break
  fi
  echo "Waiting for the database(database not ready yet) retry: $counter"
  let counter++
  sleep 1
done
php artisan v2board:install

#if [ -f "/etc/init.d/bt" ]; then
#  chown -R www $(pwd);
#fi
