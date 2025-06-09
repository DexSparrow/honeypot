if [ "$(id -u)" -ne 0 ]; then
    echo "Be cool !!"
    echo "Be root :)"
    exit 1
fi
sudo mkdir -p /var/www/honeypot
sudo cp -r ./frontend/* /var/www/honeypot/
