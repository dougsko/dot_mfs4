#
# download, compile, and install iroffer 
#
# doug prostko 2013
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
                'SessionTypes'  => [ 'shell,' ]
            ))
    end
