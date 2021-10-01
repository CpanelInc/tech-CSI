rule kobalos {
    meta:
        description = "Kobalos malware"
        author = "Marc-Etienne M.Léveillé"
        date = "2020-11-02"
        reference = "http://www.welivesecurity.com"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
    strings:
        $encrypted_strings_sizes = {
        05 00 00 00 09 00 00 00 04 00 00 00 06 00 00 00
        08 00 00 00 08 00 00 00 02 00 00 00 02 00 00 00
        01 00 00 00 01 00 00 00 05 00 00 00 07 00 00 00
        05 00 00 00 05 00 00 00 05 00 00 00 0A 00 00 00
    }
    $password_md5_digest = { 3ADD48192654BD558A4A4CED9C255C4C }
    $rsa_512_mod_header = { 10 11 02 00 09 02 00 }
    $strings_RC4_key = { AE0E05090F3AC2B50B1BC6E91D2FE3CE }
    condition:
        any of them
}

rule kobalos_ssh_credential_stealer {
    meta:
        description = "Kobalos SSH credential stealer seen in OpenSSH client"
        author = "Marc-Etienne M.Léveillé"
        date = "2020-11-02"
        reference = "http://www.welivesecurity.com"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
    strings:
        $ = "user: %.128s host: %.128s port %05d user: %.128s password: %.128s"
    condition:
        any of them
}
rule mumblehard_packer {
    meta:
        description = "Mumblehard i386 assembly code responsible for decrypting Perl code"
        author = "Marc-Etienne M.Léveillé"
        date = "2015-04-07"
        reference = "http://www.welivesecurity.com"
        version = "1"
    strings:
        $decrypt = { 31 db [1-10] ba ?? 00 00 00 [0-6] (56 5f | 89 F7)
        39 d3 75 13 81 fa ?? 00 00 00 75 02 31 d2 81 c2 ?? 00 00
        00 31 db 43 ac 30 d8 aa 43 e2 e2 }
    condition:
        $decrypt
}
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-01-10
   Identifier: Venom Rootkit
*/

/* Rule Set ----------------------------------------------------------------- */

rule Venom_Rootkit {
   meta:
      description = "Venom Linux Rootkit"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://security.web.cern.ch/security/venom.shtml"
      date = "2017-01-12"
   strings:
      $s1 = "%%VENOM%CTRL%MODE%%" ascii fullword
      $s2 = "%%VENOM%OK%OK%%" ascii fullword
      $s3 = "%%VENOM%WIN%WN%%" ascii fullword
      $s4 = "%%VENOM%AUTHENTICATE%%" ascii fullword
      $s5 = ". entering interactive shell" ascii fullword
      $s6 = ". processing ltun request" ascii fullword
      $s7 = ". processing rtun request" ascii fullword
      $s8 = ". processing get request" ascii fullword
      $s9 = ". processing put request" ascii fullword
      $s10 = "venom by mouzone" ascii fullword
      $s11 = "justCANTbeSTOPPED" ascii fullword
   condition:
      filesize < 4000KB and 2 of them
}
rule APT_MAL_WinntiLinux_Dropper_AzazelFork_May19 : azazel_fork {
    meta:
        description = "Detection of Linux variant of Winnti"
        author = "Silas Cutler (havex [@] chronicle.security), Chronicle Security"
        version = "1.0"
        date = "2019-05-15"
        TLP = "White"
        sha256 = "4741c2884d1ca3a40dadd3f3f61cb95a59b11f99a0f980dbadc663b85eb77a2a"
    strings:
        $config_decr = { 48 89 45 F0 C7 45 EC 08 01 00 00 C7 45 FC 28 00 00 00 EB 31 8B 45 FC 48 63 D0 48 8B 45 F0 48 01 C2 8B 45 FC 48 63 C8 48 8B 45 F0 48 01 C8 0F B6 00 89 C1 8B 45 F8 89 C6 8B 45 FC 01 F0 31 C8 88 02 83 45 FC 01 }
        $export1 = "our_sockets"
        $export2 = "get_our_pids"
    condition:
        uint16(0) == 0x457f and all of them
}

rule APT_MAL_WinntiLinux_Main_AzazelFork_May19 {
    meta:
        description = "Detection of Linux variant of Winnti"
        author = "Silas Cutler (havex [@] chronicle.security), Chronicle Security"
        version = "1.0"
        date = "2019-05-15"
        TLP = "White"
        sha256 = "ae9d6848f33644795a0cc3928a76ea194b99da3c10f802db22034d9f695a0c23"
    strings:
        $uuid_lookup = "/usr/sbin/dmidecode  | grep -i 'UUID' |cut -d' ' -f2 2>/dev/null"
        $dbg_msg = "[advNetSrv] can not create a PF_INET socket"
        $rtti_name1 = "CNetBase"
        $rtti_name2 = "CMyEngineNetEvent"
        $rtti_name3 = "CBufferCache"
        $rtti_name4 = "CSocks5Base"
        $rtti_name5 = "CDataEngine"
        $rtti_name6 = "CSocks5Mgr"
        $rtti_name7 = "CRemoteMsg"
    condition:
        uint16(0) == 0x457f and ( ($dbg_msg and 1 of ($rtti*)) or (5 of ($rtti*)) or ($uuid_lookup and 2 of ($rtti*)) )
}
rule SUSP_LNX_Linux_Malware_Indicators_Aug20_1 {
   meta:
      description = "Detects indicators often found in linux malware samples"
      author = "Florian Roth"
      score = 65
      reference = "Internal Research"
      date = "2020-08-03"
   strings:
      $s1 = "&& chmod +x" ascii 
      $s2 = "|base64 -" ascii
      $s3 = " /tmp" ascii 
      $s4 = "|curl " ascii
      $s5 = "whoami" ascii fullword

      $fp1 = "WITHOUT ANY WARRANTY" ascii 
      $fp2 = "postinst" ascii fullword
      $fp3 = "THIS SOFTWARE IS PROVIDED" ascii fullword
      $fp4 = "Free Software Foundation" ascii fullword
   condition:
      filesize < 400KB and
      3 of ($s*) and not 1 of ($fp*)
}
// Linux/Moose yara rules
// For feedback or questions contact us at: github@eset.com
// https://github.com/eset/malware-ioc/
//
// These yara rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2015-2016, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
private rule is_elf
{
    strings:
        $header = { 7F 45 4C 46 }

    condition:
        $header at 0
}

rule moose_1
{
    meta:
        Author      = "Thomas Dupuy"
        Date        = "2015/04/21"
        Description = "Linux/Moose malware"
        Reference   = "http://www.welivesecurity.com/wp-content/uploads/2015/05/Dissecting-LinuxMoose.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    strings:
        $s0 = "Status: OK"
        $s1 = "--scrypt"
        $s2 = "stratum+tcp://"
        $s3 = "cmd.so"
        $s4 = "/Challenge"
        $s7 = "processor"
        $s9 = "cpu model"
        $s21 = "password is wrong"
        $s22 = "password:"
        $s23 = "uthentication failed"
        $s24 = "sh"
        $s25 = "ps"
        $s26 = "echo -n -e "
        $s27 = "chmod"
        $s28 = "elan2"
        $s29 = "elan3"
        $s30 = "chmod: not found"
        $s31 = "cat /proc/cpuinfo"
        $s32 = "/proc/%s/cmdline"
        $s33 = "kill %s"

    condition:
        is_elf and all of them
}

rule moose_2
{
    meta:
        Author      = "Thomas Dupuy"
        Date        = "2016/10/02"
        Description = "Linux/Moose malware active since September 2015"
        Reference   = "http://www.welivesecurity.com/2016/11/02/linuxmoose-still-breathing/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    strings:
        $s1 = "Modules are loaded"
        $s2 = "--scrypt"
        $s3 = "http://"
        $s4 = "https://"
        $s5 = "processor "
        $s6 = "cpu model "
        $s7 = "Host: www.challpok.cn"
        $s8 = "Cookie: PHPSESSID=%s; nhash=%s; chash=%s"
        $s9 = "fail!"
        $s10 = "H3lL0WoRlD"
        $s11 = "crondd"
        $s12 = "cat /proc/cpuinfo"
        $s13 = "Set-Cookie: PHPSESSID="
        $s14 = "Set-Cookie: LP="
        $s15 = "Set-Cookie: WL="
        $s16 = "Set-Cookie: CP="
        $s17 = "Loading modules..."
        $s18 = "-nobg"

    condition:
        is_elf and 5 of them
}

rule generic_poco_openssl {
    meta:
    description = “Rule to detect statically linked POCO and OpenSSL libraries. These libraries are present in the     Drovorub-server, Drovorub-agent, and Drovorub-client binaries. Hits on this rule do not mean that the file(s) are      Drovorub-related, only that they COULD be and should be further investigated.”

    strings:
        $mw1 = { 89 F1 48 89 FE 48 89 D7 48 F7 C6 FF FF FF FF 0F 84 6B 02 00 00 48 F7 C7 FF FF FF FF 0F 84 5E 02 00 00 48 8D 2D }
        $mw2 = { 41 54 49 89 D4 55 53 F6 47 19 04 48 8B 2E 75 08 31 DB F6 45 00 03 75 }
        $mw3 = { 85 C0 BA 15 00 00 00 75 09 89 D0 5B C3 0F 1F 44 00 00 BE }
        $mw4 = { 53 8A 47 08 3C 06 74 21 84 C0 74 1D 3C 07 74 20 B9 ?? ?? ?? ?? BA FD 03 00 00 BE ?? ?? ?? ??          BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 E8 06 3C 01 77 2B 48 8B 1F 48 8B 73 10 48 89 DF E8 ?? ?? ?? ?? 48 8D 43 08 48 C7 43   10 00 00 00 00 48 C7 43 28 00 00 00 00 48 89 43 18 48 89 43 20 5B C3 }

    condition:
        all of them
}

rule drovorub_library_and_unique_strings {
    meta:
    description = “Rule to detect Drovorub-server, Drovorub-agent, and Drovorub-client binaries based on unique        strings and strings indicating statically linked libraries.”

    strings:
        $s1 = "Poco" ascii wide
        $s2 = "Json" ascii wide
        $s3 = "OpenSSL" ascii wide
        $a1 = "clientid" ascii wide
        $a2 = "-----BEGIN" ascii wide
        $a3 = "-----END" ascii wide
        $a4 = "tunnel" ascii wide
    condition:
        (filesize > 1MB and filesize < 10MB and (uint32(0) == 0x464c457f)) and (#s1 > 20 and #s2 > 15 and #s3 > 15 and all of ($a*))
}

rule drovorub_unique_network_comms_strings {
    meta:
    description = “Rule to detect Drovorub-server, Drovorub-agent, or Drovorub-client based on unique network          communication strings.”

    strings:
        $s_01 = "action" wide ascii
        $s_02 = "auth.commit" wide ascii
        $s_03 = "auth.hello" wide ascii
        $s_04 = "auth.login" wide ascii
        $s_05 = "auth.pending" wide ascii
        $s_06 = "client_id" wide ascii
        $s_07 = "client_login" wide ascii
        $s_08 = "client_pass" wide ascii
        $s_09 = "clientid" wide ascii
        $s_10 = "clientkey_base64" wide ascii
        $s_11 = "file_list_request" wide ascii
        $s_12 = "module_list_request" wide ascii
        $s_13 = "monitor" wide ascii
        $s_14 = "net_list_request" wide ascii
        $s_15 = "server finished" wide ascii
        $s_16 = "serverid" wide ascii
        $s_17 = "tunnel" wide ascii·
    condition:
        all of them
}

rule drovorub_kernel_module_unique_strings {
    meta:
    description = “Rule detects the Drovorub-kernel module based on unique strings.”

    strings:
        $s_01 = "/proc" wide ascii
        $s_02 = "/proc/net/packet" wide ascii
        $s_03 = "/proc/net/raw" wide ascii
        $s_04 = "/proc/net/tcp" wide ascii
        $s_05 = "/proc/net/tcp6" wide ascii
        $s_06 = "/proc/net/udp" wide ascii
        $s_07 = "/proc/net/udp6" wide ascii
        $s_08 = "cs02" wide ascii
        $s_09 = "do_fork" wide ascii
        $s_10 = "es01" wide ascii
        $s_11 = "g001" wide ascii
        $s_12 = "g002" wide ascii
        $s_13 = "i001" wide ascii
        $s_14 = "i002" wide ascii
        $s_15 = "i003" wide ascii
        $s_16 = "i004" wide ascii
        $s_17 = "module" wide ascii
        $s_18 = "sc!^2a" wide ascii
        $s_19 = "sysfs" wide ascii
        $s_20 = "tr01" wide ascii
        $s_21 = "tr02" wide ascii
        $s_22 = "tr03" wide ascii
        $s_23 = "tr04" wide ascii
        $s_24 = "tr05" wide ascii
        $s_25 = "tr06" wide ascii
        $s_26 = "tr07" wide ascii
        $s_27 = "tr08" wide ascii
        $s_28 = "tr09" wide ascii

    condition:
        all of them
}
