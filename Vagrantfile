# -*- mode: ruby -*-
# vi: set ft=ruby
# VirtualBox: vagrant up  → http://192.168.56.11:5001

Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"
  config.vm.hostname = "collectors-verse"
  config.vm.network "private_network", ip: "192.168.56.11"
  config.vm.network "forwarded_port", guest: 5001, host: 5001
  config.vm.provider "virtualbox" do |vb|
    vb.name = "collectors-verse"
    vb.memory = 2048
  end
  config.vm.synced_folder ".", "/opt/collectors-verse"
  config.vm.provision "shell", inline: <<-SHELL
    apt-get update -y
    apt-get install -y python3 python3-venv python3-pip
    cd /opt/collectors-verse
    python3 -m venv .venv
    .venv/bin/pip install -r requirements.txt
    cat >/etc/systemd/system/collectors-verse.service <<EOF
[Unit]
Description=Collector Verse
After=network.target
[Service]
WorkingDirectory=/opt/collectors-verse
Environment=AUTH_MODE=env
Environment=OWNER_EMAILS=keikamotushige@gmail.com
Environment=OWNER_PASSWORD=password
Environment=PER_PERSON_LIMIT=3
Environment=PORT=5001
Environment=GEMINI_API_KEY=#{ENV['GEMINI_API_KEY']}
ExecStart=/opt/collectors-verse/.venv/bin/python app.py
Restart=always
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now collectors-verse
  SHELL
end
