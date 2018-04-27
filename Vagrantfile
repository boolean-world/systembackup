Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/xenial64"
  config.vm.provider "virtualbox" do |vb|
    vb.gui = false  
    vb.memory = "640"
  end

  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    apt-get upgrade -y
    cd /tmp
    wget https://storage.googleapis.com/shellcheck/shellcheck-stable.linux.x86_64.tar.xz
    tar -xf shellcheck-stable.linux.x86_64.tar.xz
    mv shellcheck-stable/shellcheck /usr/local/bin
    rm -r shellcheck*
  SHELL
end
