import "elf"

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
    description = "Rule to detect statically linked POCO and OpenSSL libraries. These libraries are present in the Drovorub-server, Drovorub-agent, and Drovorub-client binaries. Hits on this rule do not mean that the file(s) are Drovorub-related, only that they COULD be and should be further investigated."

    strings:
        $mw1 = { 89 F1 48 89 FE 48 89 D7 48 F7 C6 FF FF FF FF 0F 84 6B 02 00 00 48 F7 C7 FF FF FF FF 0F 84 5E 02 00 00 48 8D 2D }
        $mw2 = { 41 54 49 89 D4 55 53 F6 47 19 04 48 8B 2E 75 08 31 DB F6 45 00 03 75 }
        $mw3 = { 85 C0 BA 15 00 00 00 75 09 89 D0 5B C3 0F 1F 44 00 00 BE }
        $mw4 = { 53 8A 47 08 3C 06 74 21 84 C0 74 1D 3C 07 74 20 B9 ?? ?? ?? ?? BA FD 03 00 00 BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 E8 06 3C 01 77 2B 48 8B 1F 48 8B 73 10 48 89 DF E8 ?? ?? ?? ?? 48 8D 43 08 48 C7 43 10 00 00 00 00 48 C7 43 28 00 00 00 00 48 89 43 18 48 89 43 20 5B C3 }

    condition:
        all of them
}

rule drovorub_library_and_unique_strings {
    meta:
    description = "Rule to detect Drovorub-server, Drovorub-agent, and Drovorub-client binaries based on unique        strings and strings indicating statically linked libraries."

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
    description = "Rule to detect Drovorub-server, Drovorub-agent, or Drovorub-client based on unique network communication strings."

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
        $s_17 = "tunnel" wide ascii
    condition:
        all of them
}

rule drovorub_kernel_module_unique_strings {
    meta:
    description = "Rule detects the Drovorub-kernel module based on unique strings."

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

rule linux_mal_hcrootkit_1 {
    meta:
        description = "Detects Linux HCRootkit, as reported by Avast"
        hash1 = "2daa5503b7f068ac471330869ccfb1ae617538fecaea69fd6c488d57929f8279"
        hash2 = "10c7e04d12647107e7abf29ae612c1d0e76a79447e03393fa8a44f8a164b723d"
        hash3 = "602c435834d796943b1e547316c18a9a64c68f032985e7a5a763339d82598915"
        author = "Lacework Labs"
        ref = "https://www.lacework.com/blog/hcrootkit-sutersu-linux-rootkit-analysis/"
    strings:
        $a1 = "172.96.231."
        $a2 = "/tmp/.tmp_XXXXXX"
        $s1 = "/proc/net/tcp"
        $s2 = "/proc/.inl"
        $s3 = "rootkit"
    condition:
        uint32(0)==0x464c457f and 
        ((any of ($a*)) and (any of ($s*)))
}
 
rule linux_mal_hcrootkit_2 {
    meta:
        description = "Detects Linux HCRootkit Wide, unpacked"
        hash1 = "2daa5503b7f068ac471330869ccfb1ae617538fecaea69fd6c488d57929f8279"
        hash2 = "10c7e04d12647107e7abf29ae612c1d0e76a79447e03393fa8a44f8a164b723d"
        author = "Lacework Labs"
        ref = "https://www.lacework.com/blog/hcrootkit-sutersu-linux-rootkit-analysis/"
    strings:
        $s1 = "s_hide_pids"
        $s2 = "handler_kallsyms_lookup_name"
        $s3 = "s_proc_ino"
        $s4 = "n_filldir"
        $s5 = "s_is_proc_ino"
        $s6 = "n_tcp4_seq_show"
        $s7 = "r_tcp4_seq_show"
        $s8 = "s_hide_tcp4_ports"
        $s9 = "s_proc_open"
        $s10 = "s_proc_show"
        $s11 = "s_passwd_buf"
        $s12 = "s_passwd_buf_len"
        $s13 = "r_sys_write"
        $s14 = "r_sys_mmap"
        $s15 = "r_sys_munmap"
        $s16 = "s_hide_strs"
        $s17 = "s_proc_write"
        $s18 = "s_proc_inl_operations"
        $s19 = "s_inl_entry"
        $s20 = "kp_kallsyms_lookup_name"
        $s21 = "s_sys_call_table"
        $s22 = "kp_do_exit"
        $s23 = "r_sys_getdents"
        $s24 = "s_hook_remote_ip"
        $s25= "s_hook_remote_port"
        $s26 = "s_hook_local_port"
        $s27 = "s_hook_local_ip"
        $s28 = "nf_hook_pre_routing"
    condition:
        uint32(0)==0x464c457f and 10 of them
}

rule linux_mal_suterusu_rootkit {
    meta:
        description = "Detects open source rootkit named suterusu"
        hash1 = "7e5b97135e9a68000fd3efee51dc5822f623b3183aecc69b42bde6d4b666cfe1"
        hash2 = "7b48feabd0ffc72833043b14f9e0976511cfde39fd0174a40d1edb5310768db3"
        author = "Lacework Labs"
        ref = "https://www.lacework.com/blog/hcrootkit-sutersu-linux-rootkit-analysis/"
    strings:
        $a1 = "suterusu"
        $a3 = "srcversion="
        $a4 = "Hiding PID"
        $a5 = "/proc/net/tcp"
    condition:
        uint32(0)==0x464c457f and all of them
}

rule Linux_Ransomware_LuckyJoe : tc_detection malicious
{
    meta:

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "LUCKYJOE"
        description         = "Yara rule that detects LuckyJoe ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "LuckyJoe"
        tc_detection_factor = 5

    strings:

        $main_call_p1 = {
            55 48 89 E5 48 81 EC ?? ?? ?? ?? 48 C7 45 ?? ?? ?? ?? ?? 48 C7 45 ?? ?? ?? ?? ?? 48 
            C7 45 ?? ?? ?? ?? ?? 48 C7 45 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 
            48 89 45 ?? 48 8B 55 ?? 48 8B 45 ?? 48 89 D6 48 89 C7 E8 ?? ?? ?? ?? 48 8D 75 ?? 48 
            8B 45 ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? BE ?? ?? 
            ?? ?? BF ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 89 C7 E8 
            ?? ?? ?? ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 48 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? E8 ?? ?? 
            ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? 48 8B 35 ?? ?? ?? ?? 48 83 EC ?? 48 8B 45 
            ?? 6A ?? 41 B9 ?? ?? ?? ?? 41 B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 89 C7 
            E8 ?? ?? ?? ?? 48 83 C4 ?? 48 8B 15 ?? ?? ?? ?? 48 8B 45 ?? 48 89 D6 48 89 C7 E8 ?? 
            ?? ?? ?? 48 8B 45 ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 C7 E8 ?? ?? 
            ?? ?? 48 98 48 89 45 ?? 48 8B 45 ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48
        }

        $main_call_p2 = {
            89 C7 E8 ?? ?? ?? ?? 48 98 48 89 45 ?? 48 8B 45 ?? 48 83 C0 ?? 48 89 C7 E8 ?? ?? ?? 
            ?? 48 89 45 ?? 48 8B 45 ?? 48 83 C0 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? 48 8B 45 
            ?? 89 C2 48 8B 4D ?? 48 8B 45 ?? 48 89 CE 48 89 C7 E8 ?? ?? ?? ?? 48 8B 45 ?? 89 C2 
            48 8B 4D ?? 48 8B 45 ?? 48 89 CE 48 89 C7 E8 ?? ?? ?? ?? 48 8B 55 ?? 48 8B 45 ?? 48 
            01 D0 C6 00 ?? 48 8B 55 ?? 48 8B 45 ?? 48 01 D0 C6 00 ?? 48 8B 45 ?? 48 8B 55 ?? 48 
            89 D6 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? 48 83 7D ?? ?? 75 ?? BF ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C6 BF ?? ?? ?? ?? B8 ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 ?? 74 ?? B8 
            ?? ?? ?? ?? E9 ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 45 ?? 
            48 83 7D ?? ?? 74 ?? 48 8B 55 ?? 48 8B 45 ?? BE ?? ?? ?? ?? 48 89 C7 B8
        }

        $main_call_p3 = {
            E8 ?? ?? ?? ?? 89 45 ?? 83 7D ?? ?? 79 ?? 48 8B 45 ?? 89 C7 E8 ?? ?? ?? ?? B8 ?? ?? 
            ?? ?? E9 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 8B 45 ?? 89 C7 E8 ?? ?? 
            ?? ?? 48 C7 45 ?? ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 45 
            ?? 48 83 7D ?? ?? 74 ?? EB ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? E9 ?? ?? 
            ?? ?? 48 8B 55 ?? 48 8B 45 ?? BE ?? ?? ?? ?? 48 89 C7 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            89 45 ?? 83 7D ?? ?? 79 ?? 48 8B 45 ?? 89 C7 E8 ?? ?? ?? ?? EB ?? 48 8B 45 ?? 48 89 
            C7 E8 ?? ?? ?? ?? 48 8B 45 ?? 89 C7 E8 ?? ?? ?? ?? EB ?? BF ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 48 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? 
            ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? EB ?? 8B 45 ?? 48 98 48 8B 84 
            C5 ?? ?? ?? ?? 48 89 C6 BF ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 ?? 48 98 
            48 8B 84 C5 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 83 45 ?? ?? 83 7D ?? ?? 74 ?? BF ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C7 E8 
            ?? ?? ?? ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? C9 C3 
        }

        $encrypt_files_p1 = {
            55 48 89 E5 53 48 81 EC ?? ?? ?? ?? 48 89 BD ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? BA ?? 
            ?? ?? ?? B9 ?? ?? ?? ?? 48 89 C7 48 89 D6 F3 48 A5 48 89 F2 48 89 F8 0F B7 0A 66 89 
            08 48 8D 40 ?? 48 8D 52 ?? 48 C7 45 ?? ?? ?? ?? ?? 48 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 
            48 C7 45 ?? ?? ?? ?? ?? 48 8D 95 ?? ?? ?? ?? B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 48 89 D7 
            F3 48 AB 48 8B 85 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? 48 83 7D ?? ?? 75 
            ?? 48 8B 85 ?? ?? ?? ?? 48 89 C6 BF ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? 
            ?? ?? ?? E9 ?? ?? ?? ?? 48 8D 95 ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? 48 89 D6 48 89 C7 
            E8 ?? ?? ?? ?? 48 8B 45 ?? 0F B6 40 ?? 3C ?? 0F 85 ?? ?? ?? ?? 48 8B 85 ?? ?? ?? ?? 
            48 89 C7 E8 ?? ?? ?? ?? 48 89 C3 48 8B 45 ?? 48 83 C0 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 
            01 D8 48 83 C0 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? 48 8B 85 ?? ?? ?? ?? BE ?? ?? 
            ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 84 C0 74 ?? 48 8B 45 ?? 48 8D 48 ?? 48 8B 95 ?? ?? ?? 
            ?? 48 8B 45 ?? BE ?? ?? ?? ?? 48 89 C7 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB ?? 48 8B 45 
            ?? 48 8D 48 ?? 48 8B 95 ?? ?? ?? ?? 48 8B 45 ?? BE ?? ?? ?? ?? 48 89 C7 B8 ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? 48 8D 95 ?? ?? ?? ?? 48 8B 4D ?? 48 8D 85 ?? ?? ?? ?? 48 89 CE 48 
            89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? EB ?? 48 8B 45 ?? 48 83 C0 ?? 48 89 C7 E8 ?? ?? ?? 
            ?? 48 89 C2 48 8B 45 ?? 48 89 C6 48 89 D7 E8 ?? ?? ?? ?? 85 C0 75 ?? 48 8B 45 ?? 48
        }

        $encrypt_files_p2 = {
            89 C6 BF ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? 
            ?? EB ?? 48 8D 95 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C6 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 
            89 45 ?? 48 83 7D ?? ?? 75 ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 
            8B 45 ?? 0F B6 40 ?? 3C ?? 0F 85 ?? ?? ?? ?? 48 8B 45 ?? 48 83 C0 ?? BE ?? ?? ?? ?? 
            48 89 C7 E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 45 ?? 48 83 C0 ?? BE ?? ?? ?? 
            ?? 48 89 C7 E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 45 ?? 48 83 C0 ?? 48 89 45 
            ?? 48 8B 85 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 C3 48 8B 45 ?? 48 89 C7 E8 ?? 
            ?? ?? ?? 48 01 D8 48 83 C0 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? 48 8B 85 ?? ?? ?? 
            ?? BE ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 84 C0 74 ?? 48 8B 45 ?? 48 8D 48 ?? 48 8B 
            95 ?? ?? ?? ?? 48 8B 45 ?? BE ?? ?? ?? ?? 48 89 C7 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 
            ?? 48 8B 45 ?? 48 8D 48 ?? 48 8B 95 ?? ?? ?? ?? 48 8B 45 ?? BE ?? ?? ?? ?? 48 89 C7 
            B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 8B 45 ?? 48 89 
            C7 E8 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? 48 83 7D ?? ?? 0F 
            85 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 81 C4 ?? ?? ?? ?? 5B 5D C3 
        }

        $encrypt_internal_message_p1 = {
            55 48 89 E5 53 48 83 EC ?? 48 89 7D ?? 48 89 75 ?? 48 C7 45 ?? ?? ?? ?? ?? BF ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 48 89 45 ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? 89 45 ?? 48 8B 
            45 ?? 48 89 C7 E8 ?? ?? ?? ?? 89 45 ?? 8B 45 ?? 83 C0 ?? 48 98 48 89 C7 E8 ?? ?? ?? 
            ?? 48 89 45 ?? 8B 45 ?? 83 C0 ?? 48 63 D0 48 8B 45 ?? BE ?? ?? ?? ?? 48 89 C7 E8 ?? 
            ?? ?? ?? 8B 45 ?? 48 63 D0 48 8B 4D ?? 48 8B 45 ?? 48 89 CE 48 89 C7 E8 ?? ?? ?? ?? 
            8B 45 ?? 48 98 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? 
            ?? ?? ?? 8B 45 ?? 83 E8 ?? 89 45 ?? C7 45 ?? ?? ?? ?? ?? 66 0F EF C0 F2 0F 2A 45 ?? 
            66 0F EF C9 F2 0F 2A 4D ?? F2 0F 5E C1 E8 ?? ?? ?? ?? F2 0F 2C C0 89 45 ?? 8B 45 ?? 
            0F AF 45 ?? 48 98 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? 8B 45 ?? 0F AF 45 ?? 48 63 D0 
            48 8B 45 ?? BE ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 8B 45 ?? 0F AF 45 ?? 89 C3 48 8B 
            45 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 C6 8B 45 ?? 89 C1 89 DA BF ?? ?? ?? ?? B8 ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 48 C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? 
            ?? E9 ?? ?? ?? ?? 8B 45 ?? 2B 45 ?? 3B 45 ?? 7D ?? 8B 45 ?? 2B 45 ?? 89 45 ?? 8B 45 
            ?? 48 63 D0 48 8B 45 ?? BE ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 8B 45 ?? 2B 45 ?? 89
        }

        $encrypt_internal_message_p2 = {
            C6 BF ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 ?? 48 63 D0 48 8B 45 ?? 48 8D 
            34 02 48 8B 4D ?? 48 8B 55 ?? 8B 45 ?? 41 B8 ?? ?? ?? ?? 89 C7 E8 ?? ?? ?? ?? 89 45 
            ?? 8B 45 ?? 89 C6 BF ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 7D ?? ?? 75 ?? E8 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 C2 48 8B 45 ?? 48 89 C6 48 89 D7 E8 ?? ?? ?? ?? 48 
            8B 05 ?? ?? ?? ?? 48 8B 55 ?? BE ?? ?? ?? ?? 48 89 C7 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 8B 45 ?? 
            48 89 C7 E8 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? E9 ?? ?? 
            ?? ?? 8B 45 ?? 48 63 D0 8B 45 ?? 48 63 C8 48 8B 45 ?? 48 01 C1 48 8B 45 ?? 48 89 C6 
            48 89 CF E8 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 C6 BF ?? ?? ?? ?? 
            B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 ?? 01 45 ?? 8B 45 ?? 01 45 ?? 48 8B 45 ?? 48 89 
            C7 E8 ?? ?? ?? ?? 83 45 ?? ?? 8B 45 ?? 3B 45 ?? 0F 8E ?? ?? ?? ?? 48 8B 45 ?? 48 89 
            C7 E8 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? 8B 4D ?? 48 8B 45 ?? BA ?? ?? 
            ?? ?? 89 CE 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? 
            48 89 C6 BF ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 45 ?? 48 83 C4 ?? 5B 5D 
            C3 
        }

    condition:
        uint32(0) == 0x464C457F and
        (
           all of ($main_call_p*)
        ) and
        (
           all of ($encrypt_files_p*)
        ) and 
        (
           all of ($encrypt_internal_message_p*)
        )
}

rule Linux_Virus_Vit : tc_detection malicious
{
    meta:

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "VIT"
        description         = "Yara rule that detects Vit virus."

        tc_detection_type   = "Virus"
        tc_detection_name   = "Vit"
        tc_detection_factor = 5

    strings:

      $vit_entry_point = {
        55 89 E5 81 EC 40 31 00 00 57 56 50 53 51 52 C7 85 D8 CE FF FF 00 00 00 00 C7 85 D4
        CE FF FF 00 00 00 00 C7 85 FC CF FF FF CA 08 00 00 C7 85 F8 CF FF FF B8 06 00 00 C7
        85 F4 CF FF FF AD 08 00 00 C7 85 F0 CF FF FF 50 06 00 00 6A 00 6A 00 8B 45 08 50 E8
        18 FA FF FF 89 C6 83 C4 0C 85 F6 0F 8C E6 01 00 00 6A 00 68 ?? ?? ?? ?? 56 E8 2E FA
        FF FF 83 C4 0C 85 C0 0F 8C C4 01 00 00 8B 85 FC CF FF FF 50 8D 85 00 D0 FF FF 50 56
        E8 2A FA FF FF 89 C2 8B 85 FC CF FF FF 83 C4 0C 39 C2 0F 85 9D 01 00 00 56 E8 E1 F9
        FF FF BE FF FF FF FF 6A 00 6A 00 E9
      }

      $vit_str = "vi324.tmp"

    condition:
        uint32(0) == 0x464C457F and $vit_entry_point at elf.entry_point and $vit_str
}

rule EXPL_Log4j_CVE_2021_44228_Dec21_Hard {
   meta:
      description = "Detects indicators in server logs that indicate the exploitation of CVE-2021-44228"
      author = "Florian Roth"
      reference = "https://twitter.com/h113sdx/status/1469010902183661568?s=20"
      date = "2021-12-10"
      score = 80
   strings:
      $x1 = /\$\{jndi:(ldap|ldaps|rmi|dns):\/[\/]?[a-z-\.0-9]{3,120}:[0-9]{2,5}\/[a-zA-Z\.]{1,32}\}/
      $fp1r = /(ldap|rmi|ldaps|dns):\/[\/]?(127\.0\.0\.1|192\.168\.|172\.[1-3][0-9]\.|10\.)/
   condition:
      $x1 and not 1 of ($fp*)
}

rule SUSP_Base64_Encoded_Exploit_Indicators_Dec21 {
   meta:
      description = "Detects base64 encoded strings found in payloads of exploits against log4j CVE-2021-44228"
      author = "Florian Roth"
      reference = "https://twitter.com/Reelix/status/1469327487243071493"
      date = "2021-12-10"
      score = 70
   strings:
      /* curl -s  */
      $sa1 = "Y3VybCAtcy"
      $sa2 = "N1cmwgLXMg"
      $sa3 = "jdXJsIC1zI"
      /* |wget -q -O-  */
      $sb1 = "fHdnZXQgLXEgLU8tI"
      $sb2 = "x3Z2V0IC1xIC1PLS"
      $sb3 = "8d2dldCAtcSAtTy0g"
   condition:
      1 of ($sa*) and 1 of ($sb*)
}

rule EXPL_Log4j_CallBackDomain_IOCs_Dec21_1 {
   meta:
      description = "Detects IOCs found in Log4Shell incidents that indicate exploitation attempts of CVE-2021-44228"
      author = "Florian Roth"
      reference = "https://gist.github.com/superducktoes/9b742f7b44c71b4a0d19790228ce85d8"
      date = "2021-12-12"
      score = 60
   strings:
      $xr1  = /\b(ldap|rmi):\/\/([a-z0-9\.]{1,16}\.bingsearchlib\.com|[a-z0-9\.]{1,40}\.interact\.sh|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):[0-9]{2,5}\/([aZ]|ua|Exploit|callback|[0-9]{10}|http443useragent|http80useragent)\b/
   condition:
      1 of them
}

rule EXPL_JNDI_Exploit_Patterns_Dec21_1 {
   meta:
      description = "Detects JNDI Exploit Kit patterns in files"
      author = "Florian Roth"
      reference = "https://github.com/pimps/JNDI-Exploit-Kit"
      date = "2021-12-12"
      score = 60
   strings:
      $x01 = "/Basic/Command/Base64/"
      $x02 = "/Basic/ReverseShell/"
      $x03 = "/Basic/TomcatMemshell"
      $x04 = "/Basic/JettyMemshell"
      $x05 = "/Basic/WeblogicMemshell"
      $x06 = "/Basic/JBossMemshell"
      $x07 = "/Basic/WebsphereMemshell"
      $x08 = "/Basic/SpringMemshell"
      $x09 = "/Deserialization/URLDNS/"
      $x10 = "/Deserialization/CommonsCollections1/Dnslog/"
      $x11 = "/Deserialization/CommonsCollections2/Command/Base64/"
      $x12 = "/Deserialization/CommonsBeanutils1/ReverseShell/"
      $x13 = "/Deserialization/Jre8u20/TomcatMemshell"
      $x14 = "/TomcatBypass/Dnslog/"
      $x15 = "/TomcatBypass/Command/"
      $x16 = "/TomcatBypass/ReverseShell/"
      $x17 = "/TomcatBypass/TomcatMemshell"
      $x18 = "/TomcatBypass/SpringMemshell"
      $x19 = "/GroovyBypass/Command/"
      $x20 = "/WebsphereBypass/Upload/"

      $fp1 = "<html"
   condition:
      1 of ($x*) and not 1 of ($fp*)
}

rule EXPL_Log4j_CVE_2021_44228_JAVA_Exception_Dec21_1 {
   meta:
      description = "Detects exceptions found in server logs that indicate an exploitation attempt of CVE-2021-44228"
      author = "Florian Roth"
      reference = "https://gist.github.com/Neo23x0/e4c8b03ff8cdf1fa63b7d15db6e3860b"
      date = "2021-12-12"
      score = 60
   strings:
      $xa1 = "header with value of BadAttributeValueException: "
      
      $sa1 = ".log4j.core.net.JndiManager.lookup(JndiManager"
      $sa2 = "Error looking up JNDI resource"
   condition:
      $xa1 or all of ($sa*)
}

rule EXPL_Log4j_CVE_2021_44228_Dec21_Soft {
   meta:
      description = "Detects indicators in server logs that indicate an exploitation attempt of CVE-2021-44228"
      author = "Florian Roth"
      reference = "https://twitter.com/h113sdx/status/1469010902183661568?s=20"
      date = "2021-12-10"
      modified = "2021-12-13"
      score = 60
   strings:
      $x01 = "${jndi:ldap:/"
      $x02 = "${jndi:rmi:/"
      $x03 = "${jndi:ldaps:/"
      $x04 = "${jndi:dns:/"
      $x05 = "${jndi:iiop:/"
      $x06 = "${jndi:http:/"
      $x07 = "${jndi:nis:/"
      $x08 = "${jndi:nds:/"
      $x09 = "${jndi:corba:/"

      $fp1 = "<html"
   condition:
      1 of ($x*) and not 1 of ($fp*)
}

rule EXPL_Log4j_CVE_2021_44228_Dec21_OBFUSC {
   meta:
      description = "Detects obfuscated indicators in server logs that indicate an exploitation attempt of CVE-2021-44228"
      author = "Florian Roth"
      reference = "https://twitter.com/h113sdx/status/1469010902183661568?s=20"
      date = "2021-12-12"
      modified = "2021-12-13"
      score = 60
   strings:
      $x1 = "$%7Bjndi:"
      $x2 = "%2524%257Bjndi"
      $x3 = "%2F%252524%25257Bjndi%3A"
      $x4 = "${jndi:${lower:"
      $x5 = "${::-j}${"
      $x6 = "${${env:BARFOO:-j}"
      $x7 = "${::-l}${::-d}${::-a}${::-p}"
      $x8 = "${base64:JHtqbmRp"

      $fp1 = "<html"
   condition:
      1 of ($x*) and not 1 of ($fp*)
}

rule SUSP_JDNIExploit_Indicators_Dec21 {
   meta:
      description = "Detects indicators of JDNI usage in log files and other payloads"
      author = "Florian Roth"
      reference = "https://github.com/flypig5211/JNDIExploit"
      date = "2021-12-10"
      modified = "2021-12-12"
      score = 70
   strings:
      $xr1 = /(ldap|ldaps|rmi|dns|iiop|http|nis|nds|corba):\/\/[a-zA-Z0-9\.]{7,80}:[0-9]{2,5}\/(Basic\/Command\/Base64|Basic\/ReverseShell|Basic\/TomcatMemshell|Basic\/JBossMemshell|Basic\/WebsphereMemshell|Basic\/SpringMemshell|Basic\/Command|Deserialization\/CommonsCollectionsK|Deserialization\/CommonsBeanutils|Deserialization\/Jre8u20\/TomcatMemshell|Deserialization\/CVE_2020_2555\/WeblogicMemshell|TomcatBypass|GroovyBypass|WebsphereBypass)\//
   condition:
      filesize < 100MB and $xr1
}

rule SUSP_EXPL_OBFUSC_Dec21_1{
   meta:
      description = "Detects obfuscation methods used to evade detection in log4j exploitation attempt of CVE-2021-44228"
      author = "Florian Roth"
      reference = "https://twitter.com/testanull/status/1469549425521348609"
      date = "2021-12-11"
      score = 60
   strings:
      /* ${lower:X} - single character match */
      $x1 = { 24 7B 6C 6F 77 65 72 3A ?? 7D }
      /* ${upper:X} - single character match */
      $x2 = { 24 7B 75 70 70 65 72 3A ?? 7D }
      /* URL encoded lower - obfuscation in URL */
      $x3 = "$%7blower:"
      $x4 = "$%7bupper:"
      $x5 = "%24%7bjndi:"
      $x6 = "$%7Blower:"
      $x7 = "$%7Bupper:"
      $x8 = "%24%7Bjndi:"

      $fp1 = "<html"
   condition:
      1 of ($x*) and not 1 of ($fp*)
}

rule SUSP_JDNIExploit_Error_Indicators_Dec21_1 {
   meta:
      description = "Detects error messages related to JDNI usage in log files that can indicate a Log4Shell / Log4j exploitation"
      author = "Florian Roth"
      reference = "https://twitter.com/marcioalm/status/1470361495405875200?s=20"
      date = "2021-12-10"
      modified = "2021-12-17"
      score = 70
   strings:
      $x1 = "FATAL log4j - Message: BadAttributeValueException: "
      $x2 = "Error looking up JNDI resource"
   condition:
      1 of them
}

