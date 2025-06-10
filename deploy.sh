if [ "$(id -u)" -ne 0 ]; then
    echo "Be cool !!"
    echo "Be root :)"
    exit 1
fi
sudo mkdir -p /var/www/honeypotsite
sudo cp -r ./frontend/* /var/www/honeypotsite/
sudo cp honeypotsite /etc/nginx/sites-available
sudo ln -s /etc/nginx/sites-available/honeypotsite /etc/nginx/sites-enabled/
