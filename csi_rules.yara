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
      $fp2 = "GET / HTTP/1.1"
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
      $fp2 = "/root/.bash_history"
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

rule Modified_UPX_ELF : Misc {
  meta:
    author = "@_lubiedo"
    date   = "31-08-2021"
    description = "Detect possibly modified UPX magic on ELF binaries"
  strings:
    $upx_magick = "UPX!"
    /* entries */
    $entry00 = { 50  52  E8  ??  ??  ??  ??  55  53  51  52 } // ELF64_AMD
    $entry01 = { 50 E8 }                                      // ELF_i386
    $entry02 = { 04 11 ?? ?? }                                // ELF32_MIPSEB, ELF32_MIPSEL
    $entry03 = { 18 D0 4D E2 B? }                             // ELF_ARMEL
  condition:
    filesize < 10MB and uint32be(0) == 0x7f454c46 and
    for any of ($entry*) : ( $ at elf.entry_point ) and // search for stub opcodes at entrypoint
    ( // search for UPX exec format types
      (not $upx_magick at 0xec and uint16be(filesize - 0x20) == 0x0d16) or // UPX_F_LINUX_ELF64_AMD
      (not $upx_magick at 0x98 and (uint16be(filesize - 0x20) == 0x0d17 or uint16be(filesize - 0x20) == 0x0d0c)) or // UPX_F_LINUX_ELF_i386, UPX_F_LINUX_ELF32_ARMEL
      (not $upx_magick at 0x78 and (uint16be(filesize - 0x20) == 0x0d89 or uint16be(filesize - 0x20) == 0x0d1e)) // UPX_F_LINUX_ELF32_MIPSEB, UPX_F_LINUX_ELF32_MIPSEL
    )
}

rule RAN_ELF_Hive_March_2021_1 : elf hive v5 x64
{
   meta:
        description = "Detect ELF version of Hive ransomware (x64 version)"
        author = "Arkbird_SOLG"
        reference = "Internal Research"
        date = "2021-03-26"
        hash1 = "058aabdef6b04620902c4354ce40c2e2d8ff2c0151649535c66d870f45318516"
        hash2 = "2e52494e776be6433c89d5853f02b536f7da56e94bbe86ae4cc782f85bed2c4b"
        tlp = "white"
        adversary = "Hive"
        level = "Experimental"
   strings:
        $s1 = { ff 54 1d 00 84 c0 75 43 48 83 c3 10 49 83 c7 ff 75 c6 48 8b 54 24 40 eb 02 31 d2 48 89 d1 48 c1 e1 04 49 03 0c 24 31 c0 49 3b 54 24 08 48 0f 42 c1 73 1c 48 8b }
        $s2 = { 48 8d 1d d5 b1 23 00 49 89 de 49 c1 ee 08 48 c1 e3 38 48 83 cb 28 41 b7 04 80 f9 03 75 54 48 8b 6c 24 18 48 8b 7d 00 48 8b 45 08 ff 10 48 8b 45 08 48 83 78 08 00 74 0a 48 8b 7d 00 ff 15 5a c8 23 00 48 8b 7c 24 18 ff 15 4f c8 23 00 eb }
        $s3 = { 48 8d 05 67 b2 23 00 48 89 44 24 10 48 c7 44 24 18 01 00 00 00 48 c7 44 24 20 00 00 00 00 48 8d 05 49 0b 03 00 48 89 44 24 30 48 c7 44 24 38 00 00 00 00 48 8d 74 24 10 4c 89 ff 41 ff d5 3c 03 0f 85 a1 00 00 00 48 89 d3 eb 76 4c 8d 25 e4 c8 23 00 4c 89 e7 ff 15 43 c7 23 00 88 5c 24 0f 48 8d 44 24 0f 48 89 44 24 40 48 8d 05 1e 0c 00 00 48 89 44 24 48 48 8d 05 4a ab 23 00 48 89 44 24 10 48 c7 44 24 18 01 00 00 00 48 c7 44 24 20 00 00 00 00 4c 89 74 24 30 48 c7 44 24 38 01 00 00 00 48 8d 74 24 10 4c 89 ff 41 ff d5 49 89 c6 48 89 d3 4c 89 e7 ff 15 7b c5 23 00 41 80 fe 03 75 26 48 8b 3b 48 8b 43 08 ff 10 48 8b 43 08 48 83 78 08 00 74 09 48 8b 3b ff 15 58 }
        $s4 = { 49 8b 1f 49 8b 6f 08 48 89 df ff 55 00 48 83 7d 08 00 74 09 48 89 df ff 15 5e 40 21 00 4c 89 ff ff 15 55 40 21 00 48 8b 44 24 18 f0 48 ff 08 75 0a 48 8d 7c 24 18 e8 cc 00 00 00 49 c1 e6 20 48 8b 44 24 10 f0 48 ff 08 75 0a 48 8d 7c 24 10 e8 b9 f9 ff ff 48 8d 54 24 50 4c 89 32 48 c7 42 08 00 00 00 00 48 8d 3d 3e 89 00 00 48 8d 0d 19 3b 21 00 4c 8d 05 12 3d 21 00 be 2b 00 00 00 eb 31 48 29 e8 48 8d 54 24 50 48 89 02 48 89 6a 08 4c 89 62 10 4c 89 62 18 48 8d 3d 64 88 00 00 48 8d 0d 86 3a 21 00 4c 8d 05 1f 3a 21 00 be 2f 00 00 }
   condition:
        uint32(0) == 0x464C457F and filesize > 60KB and all of ($s*) 
}

rule APT_MAL_LNX_RedMenshen_BPFDoor_Controller_May22_1 {
   meta:
      description = "Detects unknown Linux implants (uploads from KR and MO)"
      author = "Florian Roth"
      reference = "https://doublepulsar.com/bpfdoor-an-active-chinese-global-surveillance-tool-54b078f1a896"
      date = "2022-05-05"
      score = 90
      hash1 = "07ecb1f2d9ffbd20a46cd36cd06b022db3cc8e45b1ecab62cd11f9ca7a26ab6d"
      hash2 = "4c5cf8f977fc7c368a8e095700a44be36c8332462c0b1e41bff03238b2bf2a2d"
      hash3 = "599ae527f10ddb4625687748b7d3734ee51673b664f2e5d0346e64f85e185683"
      hash4 = "5b2a079690efb5f4e0944353dd883303ffd6bab4aad1f0c88b49a76ddcb28ee9"
      hash5 = "5faab159397964e630c4156f8852bcc6ee46df1cdd8be2a8d3f3d8e5980f3bb3"
      hash6 = "93f4262fce8c6b4f8e239c35a0679fbbbb722141b95a5f2af53a2bcafe4edd1c"
      hash7 = "97a546c7d08ad34dfab74c9c8a96986c54768c592a8dae521ddcf612a84fb8cc"
      hash8 = "c796fc66b655f6107eacbe78a37f0e8a2926f01fecebd9e68a66f0e261f91276"
      hash9 = "f8a5e735d6e79eb587954a371515a82a15883cf2eda9d7ddb8938b86e714ea27"
      hash10 = "fd1b20ee5bd429046d3c04e9c675c41e9095bea70e0329bd32d7edd17ebaf68a"
   strings:
      $s1 = "[-] Connect failed." ascii fullword
      $s2 = "export MYSQL_HISTFILE=" ascii fullword
      $s3 = "udpcmd" ascii fullword
      $s4 = "getshell" ascii fullword

      $op1 = { e8 ?? ff ff ff 80 45 ee 01 0f b6 45 ee 3b 45 d4 7c 04 c6 45 ee 00 80 45 ff 01 80 7d ff 00 }
      $op2 = { 55 48 89 e5 48 83 ec 30 89 7d ec 48 89 75 e0 89 55 dc 83 7d dc 00 75 0? }
      $op3 = { e8 a? fe ff ff 0f b6 45 f6 48 03 45 e8 0f b6 10 0f b6 45 f7 48 03 45 e8 0f b6 00 8d 04 02 }
      $op4 = { c6 80 01 01 00 00 00 48 8b 45 c8 0f b6 90 01 01 00 00 48 8b 45 c8 88 90 00 01 00 00 c6 45 ef 00 0f b6 45 ef 88 45 ee }
   condition:
      uint16(0) == 0x457f and
      filesize < 80KB and 2 of them or 5 of them
}

rule APT_MAL_LNX_RedMenshen_BPFDoor_Controller_May22_2 {
   meta:
      description = "Detects BPFDoor implants used by Chinese actor Red Menshen"
      author = "Florian Roth"
      reference = "https://doublepulsar.com/bpfdoor-an-active-chinese-global-surveillance-tool-54b078f1a896"
      date = "2022-05-07"
      score = 85
      hash1 = "76bf736b25d5c9aaf6a84edd4e615796fffc338a893b49c120c0b4941ce37925"
      hash2 = "96e906128095dead57fdc9ce8688bb889166b67c9a1b8fdb93d7cff7f3836bb9"
      hash3 = "c80bd1c4a796b4d3944a097e96f384c85687daeedcdcf05cc885c8c9b279b09c"
      hash4 = "f47de978da1dbfc5e0f195745e3368d3ceef034e964817c66ba01396a1953d72"
   strings:
      $opx1 = { 48 83 c0 0c 48 8b 95 e8 fe ff ff 48 83 c2 0c 8b 0a 8b 55 f0 01 ca 89 10 c9 }
      $opx2 = { 48 01 45 e0 83 45 f4 01 8b 45 f4 3b 45 dc 7c cd c7 45 f4 00 00 00 00 eb 2? 48 8b 05 ?? ?? 20 00 }

      $op1 = { 48 8d 14 c5 00 00 00 00 48 8b 45 d0 48 01 d0 48 8b 00 48 89 c7 e8 ?? ?? ff ff 48 83 c0 01 48 01 45 e0 }
      $op2 = { 89 c2 8b 85 fc fe ff ff 01 c2 8b 45 f4 01 d0 2d 7b cf 10 2b 89 45 f4 c1 4d f4 10 }
      $op3 = { e8 ?? d? ff ff 8b 45 f0 eb 12 8b 85 3c ff ff ff 89 c7 e8 ?? d? ff ff b8 ff ff ff ff c9 }
   condition:
      uint16(0) == 0x457f and
      filesize < 100KB and 2 of ($opx*) or 4 of them
}

rule APT_MAL_LNX_RedMenshen_BPFDoor_Controller_May22_3 {
   meta:
      description = "Detects BPFDoor implants used by Chinese actor Red Menshen"
      author = "Florian Roth"
      reference = "https://doublepulsar.com/bpfdoor-an-active-chinese-global-surveillance-tool-54b078f1a896"
      date = "2022-05-08"
      score = 85
      hash1 = "144526d30ae747982079d5d340d1ff116a7963aba2e3ed589e7ebc297ba0c1b3"
      hash2 = "fa0defdabd9fd43fe2ef1ec33574ea1af1290bd3d763fdb2bed443f2bd996d73"
   strings:
      $s1 = "hald-addon-acpi: listening on acpi kernel interface /proc/acpi/event" ascii fullword
      $s2 = "/sbin/mingetty /dev" ascii fullword
      $s3 = "pickup -l -t fifo -u" ascii fullword
   condition:
      uint16(0) == 0x457f and
      filesize < 200KB and 2 of them or all of them
}

rule APT_MAL_LNX_RedMenshen_BPFDoor_Controller_Generic_May22_1 {
   meta:
      description = "Detects BPFDoor malware"
      author = "Florian Roth"
      reference = "https://doublepulsar.com/bpfdoor-an-active-chinese-global-surveillance-tool-54b078f1a896"
      date = "2022-05-09"
      score = 90
      hash1 = "07ecb1f2d9ffbd20a46cd36cd06b022db3cc8e45b1ecab62cd11f9ca7a26ab6d"
      hash2 = "1925e3cd8a1b0bba0d297830636cdb9ebf002698c8fa71e0063581204f4e8345"
      hash3 = "4c5cf8f977fc7c368a8e095700a44be36c8332462c0b1e41bff03238b2bf2a2d"
      hash4 = "591198c234416c6ccbcea6967963ca2ca0f17050be7eed1602198308d9127c78"
      hash5 = "599ae527f10ddb4625687748b7d3734ee51673b664f2e5d0346e64f85e185683"
      hash6 = "5b2a079690efb5f4e0944353dd883303ffd6bab4aad1f0c88b49a76ddcb28ee9"
      hash7 = "5faab159397964e630c4156f8852bcc6ee46df1cdd8be2a8d3f3d8e5980f3bb3"
      hash8 = "76bf736b25d5c9aaf6a84edd4e615796fffc338a893b49c120c0b4941ce37925"
      hash9 = "93f4262fce8c6b4f8e239c35a0679fbbbb722141b95a5f2af53a2bcafe4edd1c"
      hash10 = "96e906128095dead57fdc9ce8688bb889166b67c9a1b8fdb93d7cff7f3836bb9"
      hash11 = "97a546c7d08ad34dfab74c9c8a96986c54768c592a8dae521ddcf612a84fb8cc"
      hash12 = "c796fc66b655f6107eacbe78a37f0e8a2926f01fecebd9e68a66f0e261f91276"
      hash13 = "c80bd1c4a796b4d3944a097e96f384c85687daeedcdcf05cc885c8c9b279b09c"
      hash14 = "f47de978da1dbfc5e0f195745e3368d3ceef034e964817c66ba01396a1953d72"
      hash15 = "f8a5e735d6e79eb587954a371515a82a15883cf2eda9d7ddb8938b86e714ea27"
      hash16 = "fa0defdabd9fd43fe2ef1ec33574ea1af1290bd3d763fdb2bed443f2bd996d73"
      hash17 = "fd1b20ee5bd429046d3c04e9c675c41e9095bea70e0329bd32d7edd17ebaf68a"
   strings:
      $op1 = { c6 80 01 01 00 00 00 48 8b 45 ?8 0f b6 90 01 01 00 00 48 8b 45 ?8 88 90 00 01 00 00 c6 45 ?? 00 0f b6 45 ?? 88 45 }
      $op2 = { 48 89 55 c8 48 8b 45 c8 48 89 45 ?? 48 8b 45 c8 0f b6 80 00 01 00 00 88 45 f? 48 8b 45 c8 0f b6 80 01 01 00 00 }
      $op3 = { 48 89 45 ?? 48 8b 45 c8 0f b6 80 00 01 00 00 88 45 f? 48 8b 45 c8 0f b6 80 01 01 00 00 88 45 f? c7 45 f8 00 00 00 00 }
      $op4 = { 48 89 7d d8 89 75 d4 48 89 55 c8 48 8b 45 c8 48 89 45 ?? 48 8b 45 c8 0f b6 80 00 01 00 00 88 45 f? }
      $op5 = { 48 8b 45 ?8 c6 80 01 01 00 00 00 48 8b 45 ?8 0f b6 90 01 01 00 00 48 8b 45 ?8 88 90 00 01 00 00 c6 45 ?? 00 0f b6 45 }
      $op6 = { 89 75 d4 48 89 55 c8 48 8b 45 c8 48 89 45 ?? 48 8b 45 c8 0f b6 80 00 01 00 00 88 45 f? 48 8b 45 c8 }
   condition:
      uint16(0) == 0x457f and
      filesize < 200KB and 2 of them or 4 of them
}

rule panchan {
    meta:
        author = "Stiv Kupchik"
        filetype = "ELF"
        version = "1.0"
        reference = ""

    strings:
        $go_magic = "\xFF Go buildinf:" ascii // All go binaries have this magic header - we use this to verify we have a Go binary
        $str_p2p_header = "pan-chan's mining rig hi!" ascii
        $str_sharepeer = "sharepeer" ascii
        $str_sharerigconfig = "sharerigconfig" ascii
        $str_godmode_login = "(*ﾟーﾟ)/)／＼" ascii
        $public_key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwaZwxk7A5U7cejo/8STO\x0a6TjEArLaG+EXhWQxjg2jwgtmNfYTOHg5Ss9e3vHdZCTEo/OIdJQC6If7POa+NbbR\x0a9HkagE0ZYjTXTWNP0PgUxEmcboYkO38fxMpI7Gp+331xzaYT4VY8t5Ko01lvkIoV\x0amxjDKJhSiUbCnFkz76qbjZHpLa0hcpXgO1sXx1IciwaVqlLpzncbmK7Ok3ymS3Ee\x0aG3KWQ/NEm4x8yHx07NI6b/cV/z5YOja9jul7POK8Owo17HuFIhfICgFk8Goc1VnM\x0aiypx91Thqz7IWaF5fTFdBp+0p/cUajcA6vDd3TM0FDzT4HafWppjsofOSoLvTwnq\x0aCwIDAQAB"

    condition:
        $go_magic and (all of ($str*) or $public_key)
}

rule Linux_Trojan_Ebury_7b13e9b6 {
    meta:
        id = "7b13e9b6-ce96-4bd3-8196-83420280bd1f"
        fingerprint = "a891724ce36e86637540f722bc13b44984771f709219976168f12fe782f08306"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ebury"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8B 44 24 10 4C 8B 54 24 18 4C 8B 5C 24 20 8B 5C 24 28 74 04 }
    condition:
        all of them
}

rule Dacls_Trojan_Linux {
    meta:
        Author = "Adam M. Swanda"
        Repo = "https://github.com/deadbits/yara-rules"

    strings:
        $cls00 = "c_2910.cls" ascii fullword
        $cls01 = "k_3872.cls" ascii fullword

        $str00 = "{\"result\":\"ok\"}" ascii fullword
        $str01 = "SCAN  %s  %d.%d.%d.%d %d" ascii fullword
        $str02 = "/var/run/init.pid" ascii fullword
        $str03 = "/flash/bin/mountd" ascii fullword
        $str04 = "Name:" ascii fullword
        $str05 = "Uid:" ascii fullword
        $str06 = "Gid:" ascii fullword
        $str08 = "PPid:" ascii fullword
        $str09 = "session_id" ascii fullword

    condition:
        uint32be(0x0) == 0x7f454c46
        and
        (
            (all of ($cls*))

            or

            (all of ($str*))

        )
}

rule ACBackdoor_ELF: linux malware backdoor {
    meta:
        author = "Adam M. Swanda"
        date = "Nov 2019"
        reference = "https://www.intezer.com/blog-acbackdoor-analysis-of-a-new-multiplatform-backdoor/"

    strings:
        $ua_str = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)" ascii fullword
        $header1 = "Access-Control:" ascii fullword
        $header2 = "X-Access" ascii

        $initd = "/etc/init.d/update-notifier" ascii fullword
        $str001 = "#!/bin/sh -e" ascii fullword
        $str002 = "### BEGIN INIT INFO" ascii fullword
        $str003 = "# Provides:          update-notifier" ascii fullword
        $str004 = "# Required-Start:    $local_fs" ascii fullword
        $str005 = "# Required-Stop:" ascii fullword
        $str006 = "# Default-Start:     S" ascii fullword
        $str007 = "# Default-Stop:" ascii fullword
        $str008 = "### END INIT INFO" ascii fullword
        $str010 = "  *) echo \"Usage: $0 {start|stop|restart|force-reload}\" >&2; ;;" ascii fullword
        $str011 = "esac" ascii fullword
        $str012 = "[ -x /usr/local/bin/update-notifier ] \\" ascii fullword
        $str013 = "    && exec /usr/local/bin/update-notifier" ascii fullword
        $rcd01 = "/etc/rc2.d/S01update-notifier" ascii fullword
        $rcd02 = "/etc/rc3.d/S01update-notifier" ascii fullword
        $rcd03 = "/etc/rc5.d/S01update-notifier" ascii fullword

    condition:
        /* trigger = '{7f 45 4c 46}' - ELF magic bytes */
        (uint32be(0x0) == 0x7f454c46)
        and
        (
            ($ua_str and all of ($header*) and $initd and all of ($rcd*))
            or
            (
                $ua_str and all of ($header*) and 10 of ($str*)
            )
        )
}

rule Linux_Golang_Ransomware: linux ransomware golang {
    meta:
        author = "Adam M. Swanda"
        reference = "https://www.fortinet.com/blog/threat-research/new-golang-ransomware-targeting-linux-systems.html"

    strings:
        $str001 = "1) Email: fullofdeep@protonmail.com" ascii fullword
        $str002 = "https://ipapi.com/json/idna:" ascii
        $str003 = "%s.encrypted.localhost" ascii
        $str004 = ".local.onion" ascii
        $str005 = "DO NOT TRY TO DO SOMETHING TO YOUR FILES YOU WILL BRAKE YOUR DATA" ascii fullword
        $str006 = "4.We can decrypt few files in quality the evidence that we have the decoder." ascii fullword

    condition:
        uint32be(0x0) == 0x7f454c46
        and all of them
}

rule GodLua_Linux: linuxmalware {
   meta:
      Author = "Adam M. Swanda"
      Website = "https://www.deadbits.org"
      Repo = "https://github.com/deadbits/yara-rules"
      Date = "2019-07-18"

   strings:

      $tmp0 = "/tmp" ascii fullword
      $tmp1 = "TMPDIR" ascii

      $str1 = "\"description\": \"" ascii fullword
      $str2 = "searchers" ascii fullword
      $str3 = "/dev/misc/watchdog" ascii fullword
      $str4 = "/dev/wdt" ascii fullword
      $str5 = "/dev/misc/wdt"
      $str6 = "lcurl.safe" ascii fullword
      $str7 = "luachild" ascii fullword
      $str8 = "cjson.safe" ascii fullword
      $str9 = "HostUrl" ascii fullword
      $str10 = "HostConnect" ascii fullword
      $str11 = "LUABOX" ascii fullword
      $str12 = "Infinity" ascii fullword
      $str13 = "/bin/sh" ascii fullword
      $str14 = /\.onion(\.)?/ ascii fullword
      $str15 = "/etc/resolv.conf" ascii fullword
      $str16 = "hosts:" ascii fullword

      $resolvers = /([0-9]{1,3}\.){3}[0-9]{1,3}:53,([0-9]{1,3}\.){3}[0-9]{1,3},([0-9]{1,3}\.){3}[0-9]{1,3}:5353,([0-9]{1,3}\.){3}[0-9]{1,3}:443/ ascii

      $identifier0 = "$LuaVersion: God " ascii
      $identifier1 = /fbi\/d\.\/d.\/d/ ascii
      $identifier2 = "Copyright (C) FBI Systems, 2012-2019, https://fbi.gov" fullword ascii
      $identifier3 = "God 5.1"

   condition:
      uint16(0) == 0x457f
      and
      (
         all of them
         or
         (
            any of ($identifier*)
            and $resolvers
            and any of ($tmp*)
            and 4 of ($str*)
         )
         or
         (
            any of ($identifier*)
            and any of ($tmp*)
            and 4 of ($str*)
         )
      )
}

rule Winnti_Linux: linuxmalware {
   meta:
      Author = "Adam M. Swanda"
      Website = "https://www.deadbits.org"
      Repo = "https://github.com/deadbits/yara-rules"
      Date = "2019-07-18"

   strings:
      $str0 = "HIDE_THIS_SHELL=x"
      $str1 = "/usr/sbin/dmidecode  | grep -i 'UUID' |cut -d' ' -f2 2>/dev/null" ascii fullword
      $str2 = "mutex.max:  %lu" ascii fullword
      $str3 = "mutex.err:  %lu" ascii fullword
      $str4 = "/tmp/ans.log" ascii fullword
      $str5 = "mutex.used: %lu" ascii fullword
      $str6 = "Warning: Some of the worker threads may have failed to exit." ascii fullword
      $str7 = "line %d - " ascii fullword
      $str8 = "Warning an error has occurred when trying to obtain a worker task." ascii fullword
      $str9 = "6CMutex" ascii fullword
      $str10 = "Failed to obtain an empty task from the free tasks queue." ascii fullword
      $str11 = "A problem was detected in the queue (expected NULL, but found a different value)." ascii fullword
      $str12 = "Failed to a task to the free tasks queue during initialization." ascii fullword
      $str13 = "/var/run/libudev1.pid" ascii fullword
      $str14 = "__pthread_key_create" ascii fullword
      $str15 = "The threadpool received as argument is NULL." ascii fullword
      $str16 = "Failed to enqueue a task to free tasks queue." ascii fullword
      $str17 = "Failed to obtain a task from the jobs queue." ascii fullword
      $str18 = "Failed to add a new task to the tasks queue." ascii fullword
      $str19 = "setsockopt  failed" ascii fullword
      $str20 = "libxselinux.so" ascii fullword
      $str21 = "/lib/libxselinux" ascii fullword

    condition:
      uint16(0) == 0x457f
      and
      8 of them
}

rule WatchDog_Botnet: botnet linuxmalware exploitation cve_2019_11581 cve_2019_10149 {
    meta:

        Author = "Adam M. Swanda"
        Website = "https://www.deadbits.org"
        Repo = "https://github.com/deadbits/yara-rules"
        Date = "2019-07-22"
        Reference = "https://twitter.com/polarply/status/1153232987762376704"

    strings:

        // $email = "jeff4r@watchbog.com"
        $py0 = "libpython" ascii
        //$py1 = "jail.py" ascii fullword

        //$rcpt1 = "RCPT TO:<${run{\x2Fbin\x2Fsh\t-c\t\x22bash\x20\x2Ftmp\x2Fbaby\x22}}@localhost>" ascii fullword
        //$rcpt2 = /RCPT TO:<\$\{run\{\\x2Fbin\\x2Fsh\\t-c\\t\\x22curl\\x20https\\x3a\\x2F\\x2Fpastebin.com\\x2Fraw/

        $str0 = "*/3 * * * * root wget -q -O- https://pastebin.com/raw/" ascii
        $str1 = "*/1 * * * * root curl -fsSL https://pastebin.com/raw/" ascii
        $str6 = "onion.to"
        $str7 = /https?:\/\/pastebin.com\/raw/ nocase
        $str8 = "http://icanhazip.com/"
        $str9 = "http://ident.me/"

        $scan0 = "Scan_run"
        $scan1 = "scan_nexus"
        $scan2 = "scan_couchdb"
        $scan3 = "scan_jenkins"
        $scan4 = "scan_laravel"
        $scan5 = "scan_redis"

        $exploit01 = "CVE_2015_4335"
        $exploit02 = "CVE_2018_1000861"
        $exploit03 = "CVE_2018_8007"
        $exploit04 = "CVE_2019_1014"
        $exploit05 = "CVE_2019_11581"
        $exploit06 = "CVE_2019_7238"

        $pwn0 = "pwn_couchdb"
        $pwn1 = "pwn_jenkins"
        $pwn2 = "pwn_jira"
        $pwn3 = "pwn_nexus"
        $pwn4 = "pwn_redis"
        $pwn5 = "pwn_exim"

        $payload = /payload(s)/ nocase
        $jira_token = "atlassian.xsrf.token=%s" ascii fullword
        $jira_cmd = "set ($cmd=\"%s\")" ascii fullword
        $jira_id = "JSESSIONID=%s" ascii fullword

        /*
        dont know if i really want to add these
            $user_agent00 = "Mozilla_4_0_compatible_MSIE_6_0"
            $user_agent00 = "Mozilla_4_0_compatible_MSIE_6_0_2"
            $user_agent00 = "Mozilla_4_0_compatible_MSIE_6_0_3"
            $user_agent00 = "Mozilla_4_0_compatible_MSIE_7_0"
            $user_agent00 = "Mozilla_4_0_compatible_MSIE_7_0_2"
            $user_agent00 = "Mozilla_4_0_compatible_MSIE_7_0_3"
            $user_agent00 = "Mozilla_4_0_compatible_MSIE_7_0_4"
            $user_agent00 = "Mozilla_4_0_compatible_MSIE_7_0b"
            $user_agent00 = "Mozilla_5_0_Macintosh_Intel_Mac"
            $user_agent00 = "Mozilla_5_0_Windows_NT_5_1_Apple"
            $user_agent00 = "Mozilla_5_0_Windows_NT_6_1_WOW64"
            $user_agent00 = "Mozilla_5_0_Windows_NT_6_1_WOW64_2"
            $user_agent00 = "Mozilla_5_0_Windows_NT_6_1_WOW64_3"
            $user_agent00 = "Mozilla_5_0_Windows_NT_6_1_WOW64_4"
            $user_agent00 = "Mozilla_5_0_Windows_NT_6_1_WOW64_5"
            $user_agent00 = "Mozilla_5_0_Windows_NT_6_1_WOW64_6"
            $user_agent00 = "Mozilla_5_0_Windows_NT_6_1_Win64"
            $user_agent00 = "Mozilla_5_0_Windows_U_MSIE_9_0_W"
            $user_agent00 = "Mozilla_5_0_Windows_U_Windows_NT"
            $user_agent00 = "Mozilla_5_0_Windows_U_Windows_NT_2"
            $user_agent00 = "Mozilla_5_0_Windows_U_Windows_NT_3"
            $user_agent00 = "Mozilla_5_0_X11_Linux_i686_U_Gec"
            $user_agent00 = "Mozilla_5_0_X11_U_Linux_en_US_Ap"
            $user_agent00 = "Mozilla_5_0_X11_U_Linux_i686_en"
            $user_agent00 = "Mozilla_5_0_X11_U_Linux_x86_64_z"
            $user_agent00 = "Mozilla_5_0_X11_Ubuntu_Linux_x86"
            $user_agent00 = "Mozilla_5_0_compatible_MSIE_8_0"
            $user_agent00 = "Mozilla_5_0_compatible_MSIE_9_0"
            $user_agent00 = "Mozilla_5_0_compatible_MSIE_9_0_2"
            $user_agent00 = "Mozilla_5_0_compatible_MSIE_9_0_3"
            $user_agent00 = "Mozilla_5_0_iPad_U_CPU_OS_4_2_1"
        */

    condition:
        uint32be(0x0) == 0x7f454c46
        and $py0
        and
        (
            (all of ($pwn*) and all of ($scan*))
            or
            ($payload and all of ($jira*) and 5 of ($str*))
            or
            (all of ($str*) and all of ($exploit*))
        )
}

rule RedGhost_Linux: postexploitation linuxmalware {
    meta:

        Author = "Adam M. Swanda"
        Website = "https://www.deadbits.org"
        Repo = "https://github.com/deadbits/yara-rules"
        Date = "2019-08-07"
        Reference = "https://github.com/d4rk007/RedGhost/"

    strings:
        $name = "[ R E D G H O S T - P O S T  E X P L O I T - T O O L]" ascii

        $feature0 = "Payloads" ascii
        $feature1 = "SudoInject" ascii
        $feature2 = "lsInject" ascii
        $feature3 = "Crontab" ascii
        $feature4 = "GetRoot" ascii
        $feature5 = "Clearlogs" ascii
        $feature6 = "MassinfoGrab" ascii
        $feature7 = "CheckVM" ascii
        $feature8 = "MemoryExec" ascii
        $feature9 = "BanIP" ascii

        $func0 = "checkVM(){" ascii
        $func1 = "memoryexec(){" ascii
        $func2 = "banip(){" ascii
        $func3 = "linprivesc(){" ascii
        $func4 = "dirty(){" ascii
        $func5 = "Ocr(){" ascii
        $func6 = "clearlog(){" ascii
        $func7 = "conmethods(){" ascii
        $func8 = "add2sys(){" ascii

        //$header = "#!/bin/bash" ascii

    condition:
      // #!/bin/bash header
      (uint16be(0x0) == 0x2321 and 
      for any i in (0..64) : (
          uint16be(i) == 0x2f62 and uint8(i+2) == 0x68
      ))
      and
      ($name or 5 of them)
}

rule Linux_Trojan_Pornoasset_927f314f {
    meta:
        author = "Elastic Security"
        id = "927f314f-2cbb-4f87-b75c-9aa5ef758599"
        fingerprint = "7214d3132fc606482e3f6236d291082a3abc0359c80255048045dba6e60ec7bf"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Pornoasset"
        reference_sample = "d653598df857535c354ba21d96358d4767d6ada137ee32ce5eb4972363b35f93"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C3 D3 CB D3 C3 48 31 C3 48 0F AF F0 48 0F AF F0 48 0F AF F0 48 }
    condition:
        all of them
}

rule Rootkit_Linux_Libprocesshider {
    meta:
        description = "Detects libprocesshider Linux process hiding library"
        author = "mmuir@cadosecurity.com"
        date = "2202-05-12"
        license = "Apache License 2.0"
    strings:
        $str1 = "readdir"
        $str2 = "/proc/self/fd/"
        $str3 = "processhider.c"
        $str4 = "get_process_name"
        $str5 = "/proc/%s/stat"
        $str6 = "process_to_filter"
        $str7 = "get_dir_name"
    condition:
        uint32(0) == 0x464c457f and
        uint8(16) == 0x0003 and
        all of them
}


