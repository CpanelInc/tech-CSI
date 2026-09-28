import "elf"
import "math"
import "hash"

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

rule SUSP_EXPL_OBFUSC_Dec21_1 {
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

rule UNK_APT_MelofeeImplant {
    meta:
        author = "Exatrack"
        date =   "2023-03-03"
        update =   "2023-03-03"
        description = "Detects the Melofee implant"
        tlp =  "CLEAR"
        sample_hash = "a5a4284f87fd475b9474626040d289ffabba1066fae6c37bd7de9dabaf65e87a,f3e35850ce20dfc731a6544b2194de3f35101ca51de4764b8629a692972bef68,8d855c28744dd6a9c0668ad9659baf06e5e448353f54d2f99beddd21b41390b7"

    strings:
        $str_melofee_implant_01 = "10PipeSocket"
        $str_melofee_implant_02 = "ikcp_ack_push"
        $str_melofee_implant_03 = "TLSSocketEE"
        $str_melofee_implant_04 = "/tmp/%s.lock"
        $str_melofee_implant_05 = "neosmart::WaitForMultipleEvents"
        $str_melofee_implant_06 = "9TLSSocket"
        $str_melofee_implant_07 = "7VServer"
        $str_melofee_implant_08 = "N5boost6detail13sp_ms_deleterI13UdpSocketWrapEE"
        $str_melofee_implant_09 = "UdpServerWrap"
        $str_melofee_implant_10 = "KcpUpdater"
        $str_melofee_implant_11 = "SelfForwardServer"

        $str_command_parsing_01 = {3? 01 00 05 00 ?? ?? ?? ?? 00 00 3? 01 00 05 00 ?? ?? 3? 05 00 04 00}
        $str_command_parsing_02 = {3? 04 00 04 00 ?? ?? ?? ?? 00 00 3? 04 00 04 00 ?? ?? 3? 05 00 01 00}
        $str_command_parsing_03 = {3? 01 00 07 00 ?? ?? ?? ?? 00 00 3? 01 00 09 00 ?? ?? ?? ?? ?? 00 3? 01 00 06 00 }

    condition:
        3 of them
}

rule UNK_APT_Melofee_Installer {
    meta:
        author = "Exatrack"
        date =   "2023-03-15"
        update =   "2023-03-15"
        description = "Detects the installer for melofee malware"
        score =   80
        tlp =  "AMBER"
        source =  "Exatrack"
        sample_hash = "758b0934b7adddb794951d15a6ddcace1fa523e814aa40b55e2d071cf2df81f0"

    strings:
        $str_melofee_installer_01 = "#Script for starting modules"
        $str_melofee_installer_02 = "#End script"
        $str_melofee_installer_03 = "/etc/intel_audio/"
        $str_melofee_installer_04 = "rm -fr /etc/rc.modules"
        $str_melofee_installer_05 = "-i <data file>      Install"
        $str_melofee_installer_06 = "cteate home folder failed"
        $str_melofee_installer_07 = "create rootkit file failed"
        $str_melofee_installer_08 = "create auto start file failed"
        $str_melofee_installer_09 = "Remove Done!" // only 3 files on VT with this :D
        $str_melofee_installer_10 = "Unkown option %c\n"

    condition:
        any of them
}

rule UNK_APT_Alien_Implant {
    meta:
        author = "Exatrack"
        date =   "2023-03-03"
        update =   "2023-03-03"
        description = "Detects an unknown implant from AlienManager family, maybe related to melofee"
        tlp =  "CLEAR"
        sample_hash = "3535f45bbfafda863665c41d97d894c39277dfd9af1079581d28015f76669b88,"

    strings:
        $str_alien_01 = "[+]  Connect %s Successed,Start Transfer..."
        $str_alien_02 = "Alloc buffer to decrypt data error, length == %d."
        $str_alien_03 = "pel_decrypt_msg data error, error"
        $str_alien_04 = "encrypt data error, length == %d."
        $str_alien_05 = "DoRecvOverlapInternal error!"
        $str_alien_06 = "Socks Listen port is %d,Username is %s, password is %s"
        $str_alien_07 = "Start port mapping error! remoteAddr=%s remotePort=%d localAddr=%s localPort=%d"
        $str_alien_08 = "OnCmdSocksStart error!"
        $str_alien_09 = "The master isn't readable!"
        $str_alien_10 = "ConnectBypassSocks proxy:%s:%d error!"
        $str_alien_11 = "ConnectBypassSocks to %s %d"
        $str_alien_12 = "now datetime: %d-%d-%d %d:%d:%d"
        $str_alien_13 = "Not during working hours! Disconnect!"
        $str_alien_14 = "Example: ./AlienReverse --reverse-address=192.168.1.101:80 --reverse-password=123456"
        $str_alien_15 = "Not during working hours! Disconnect!"
        $str_alien_16 = "SocksManager.cpp"
        $str_alien_17 = "connect() in app_connect"
        $str_alien_18 = "They send us %hhX %hhX"
        $str_alien_19 = "your input directory is not exist!"
        $str_alien_20 = "Send data to local error ==> %d.\n"

    condition:
        any of them
}

rule MALWARE_Multi_Exaramel {
    meta:
        author = "ditekSHen"
        description = "Exaramel Windows/Linux backdoor payload"
        clamav_sig1 = "MALWARE_Linux.Backdoor.Exaramel"
    strings:
        // Linux payload
        $s1 = "vendor/golang_org/x/crypto/" ascii
        $s2 = "vendor/golang_org/x/net/http2" ascii
        $s3 = "vendor/golang_org/x/text/unicode" ascii
        $s4 = "vendor/golang_org/x/text/transform" ascii
        $s5 = "config.json" ascii
        $cmd1 = "App.Update" ascii
        $cmd2 = "App.Delete" ascii
        $cmd3 = "App.SetProxy" ascii
        $cmd4 = "App.SetServer" ascii
        $cmd5 = "App.SetTimeout" ascii
        $cmd6 = "IO.WriteFile" ascii
        $cmd7 = "IO.ReadFile" ascii
        $cmd8 = "OS.ShellExecute" ascii
        $cmd9 = "awk 'match($0, /(upstart|systemd|sysvinit)/){ print substr($0, RSTART, RLENGTH);exit;" ascii
    condition:
        (uint16(0) == 0x457f and (all of ($s*) and 6 of ($cmd*)))
}

rule MALWARE_Linux_ChaChaDDoS {
    meta:
        author = "ditekSHen"
        description = "ChaChaDDoS variant of XorDDoS payload"
    strings:
        $x1 = "[kworker/1:1]" ascii
        $x2 = "-- LuaSocket toolkit." ascii
        $x3 = "/etc/resolv.conf" ascii
        $x4 = "\"macaddress=\" .. DEVICE_MAC .. \"&device=\" .." ascii
        $x5 = "easy_attack_dns" ascii
        $x6 = "easy_attack_udp" ascii
        $x7 = "easy_attack_syn" ascii
        $x8 = "syn_probe" ascii
    condition:
    uint16(0) == 0x457f and 6 of them
}

rule MALWARE_Linux_XORDDoS {
    meta:
        author = "ditekSHen"
        description = "Detects XORDDoS"
    strings:
        $s1 = "for i in `cat /proc/net/dev|grep :|awk -F: {'print $1'}`; do ifconfig $i up& done" fullword ascii
        $s2 = "cp /lib/libudev.so /lib/libudev.so.6" fullword ascii
        $s3 = "sed -i '/\\/etc\\/cron.hourly\\/gcc.sh/d' /etc/crontab && echo '*/3 * * * * root /etc/cron.hourly/gcc.sh' >> /etc/crontab" fullword ascii
        $s4 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; TencentTraveler ; .NET CLR 1.1.4322)" fullword ascii
    condition:
      uint32(0) == 0x464c457f and 3 of them
}

rule Linux_Trojan_Xorddos_2aef46a6 {
    meta:
        author = "Elastic Security"
        id = "2aef46a6-6daf-4f02-b1b4-e512cea12e53"
        fingerprint = "e583729c686b80e5da8e828a846cbd5218a4d787eff1fb2ce84a775ad67a1c4d"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Xorddos"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 25 64 2D 2D 25 73 5F 25 64 3A 25 73 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_a6572d63 {
    meta:
        author = "Elastic Security"
        id = "a6572d63-f9f3-4dfb-87e6-3b0bafd68a79"
        fingerprint = "fd32a773785f847cdd59d41786a8d8a7ba800a71d40d804aca51286d9bb1e1f0"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "2ff33adb421a166895c3816d506a63dff4e1e8fa91f2ac8fb763dc6e8df59d6e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C8 0F B6 46 04 0F B6 56 05 C1 E0 08 09 D0 89 45 CC 0F B6 46 06 0F B6 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_e41143e1 {
    meta:
        author = "Elastic Security"
        id = "e41143e1-52d9-45c7-b19f-a5475b18a510"
        fingerprint = "f621a2e8c289772990093762f371bb6d5736085695881e728a0d2c013c2ad1d4"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Xorddos"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 73 1E 80 3C 06 00 8D 14 30 8D 4C 37 FF 74 0D EB 36 0F B6 42 01 83 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_0eb147ca {
    meta:
        author = "Elastic Security"
        id = "0eb147ca-ec6d-4a6d-b807-4de8c1eff875"
        fingerprint = "6a1667f585a7bee05d5aece397a22e376562d2b264d3f287874e5a1843e67955"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "45f25d2ffa2fc2566ed0eab6bdaf6989006315bbbbc591288be39b65abf2410b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 83 45 F0 01 8B 45 F0 89 45 E8 8B 45 E8 83 C4 18 5F 5D C3 55 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_884cab60 {
    meta:
        author = "Elastic Security"
        id = "884cab60-214f-4879-aa51-c00de1a5ffc4"
        fingerprint = "47895e9c8acf66fc853c7947dc53730967d5a4670ef59c96569c577e1a260a72"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Xorddos"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E4 8B 51 64 F6 C2 10 75 12 89 CB 89 D1 83 C9 40 89 D0 F0 0F B1 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_ba961ed2 {
    meta:
        author = "Elastic Security"
        id = "ba961ed2-b410-4da5-8452-a03cf5f59808"
        fingerprint = "fff4804164fb9ff1f667d619b6078b00a782b81716e217ad2c11df80cb8677aa"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "45f25d2ffa2fc2566ed0eab6bdaf6989006315bbbbc591288be39b65abf2410b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F8 C9 C3 55 89 E5 83 EC 38 C7 45 F8 FF FF FF FF C7 45 FC FF FF }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_2084099a {
    meta:
        author = "Elastic Security"
        id = "2084099a-1df6-4481-9d13-3a5bd6a53817"
        fingerprint = "dfb813a5713f0e7bdb5afd500f1e84c6f042c8b1a1d27dd6511dca7f2107c13b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Xorddos"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8B 45 FC 8B 50 18 8B 45 08 89 50 18 8B 45 FC 8B 40 08 85 C0 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_61c88137 {
    meta:
        author = "Elastic Security"
        id = "61c88137-02f6-4339-b8fc-04c72a5023aa"
        fingerprint = "c09b31424a54e485fe5f89b4ab0a008df6e563a75191f19de12113890a4faa39"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "479ef38fa00bb13a3aa8448aa4a4434613c6729975e193eec29fc5047f339111"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 8B C1 8B 0C 24 8D 64 24 FC 89 0C 24 8B 4D E8 87 0C 24 96 8D 64 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_debb98a1 {
    meta:
        author = "Elastic Security"
        id = "debb98a1-c861-4458-8bff-fae4f00a17dc"
        fingerprint = "2c5688a82f7d39b0fceaf4458856549b1bce695a160a864f41b12b42e86e3745"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "494f549e3dd144e8bcb230dd7b3faa8ff5107d86d9548b21b619a0318e362cad"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F4 87 5D F4 5B 9C 51 8B 4C 24 04 8D 49 2A 87 4C 24 04 89 4C }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_1d6e10fd {
    meta:
        author = "Elastic Security"
        id = "1d6e10fd-7404-4597-a97d-cc92849d84f4"
        fingerprint = "bf9d971a13983f1d0fdc8277e76cd1929523e239ce961316fe1f44cbdf0638a8"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "4c7851316f01ae84ee64165be3ba910ab9b415d7f0e2f5b7e5c5a0eaefa3c287"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 04 9C 83 C5 7B 9D 8D 6D 85 87 54 24 00 9C 83 C5 26 9D 8D }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_e3ffbbcc {
    meta:
        author = "Elastic Security"
        id = "e3ffbbcc-7751-4d96-abec-22dd9618cab1"
        fingerprint = "d5d5117a31da1a0ac3ef4043092eed47e2844938da9d03e2b68a66658e300175"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "28b7ddf2548411910af033b41982cdc74efd8a6ef059a54fda1b6cbd59faa8f6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FF 10 52 FB FF D0 52 FB FF 00 52 FB FF D0 52 FB FF F0 51 FB }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_30f3b4d4 {
    meta:
        author = "Elastic Security"
        id = "30f3b4d4-e634-418e-a9d5-7f12ef22f9ac"
        fingerprint = "de1002eb8e9aae984ee5fe2a6c1f91845dab4861e09e01d644248cff8c590e5b"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "5b15d43d3535965ec9b84334cf9def0e8c3d064ffc022f6890320cd6045175bc"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 70 9C 83 C5 17 9D 8D 6D E9 0F 10 74 24 60 8B F6 0F 10 6C }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_ca75589c {
    meta:
        author = "Elastic Security"
        id = "ca75589c-6354-411b-b0a5-8400e657f956"
        fingerprint = "0bcaeae9ec0f5de241a05c77aadb5c3f2e39c84d03236971a0640ebae528a496"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "0448c1b2c7c738404ba11ff4b38cdc8f865ccf1e202f6711345da53ce46e7e16"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 6D E0 25 01 00 00 00 55 8B EC C9 87 D1 87 0C 24 87 D1 8D 64 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_7909cdd2 {
    meta:
        author = "Elastic Security"
        id = "7909cdd2-8a49-4f51-ae16-1ffe321a29d4"
        fingerprint = "5c982596276c8587a88bd910bb2e75a7f72ea7a57c401ffa387aced33f9ac2b9"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "0a4a5874f43adbe71da88dc0ef124f1bf2f4e70d0b1b5461b2788587445f79d9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { A5 07 00 EC C5 19 08 EC C5 19 08 18 06 00 00 18 06 00 00 06 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_2522d611 {
    meta:
        author = "Elastic Security"
        id = "2522d611-4ce3-4583-87d6-e5631b62d562"
        fingerprint = "985885a6b5f01e8816027f92148d2496a5535f3c15de151f05f69ec273291506"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "0c2be53e298c285db8b028f563e97bf1cdced0c4564a34e740289b340db2aac1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 04 57 8B 7C 24 02 5F 87 44 24 00 50 8B 44 24 04 8D 40 42 87 44 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_56bd04d3 {
    meta:
        author = "Elastic Security"
        id = "56bd04d3-6b52-43f4-b170-637feb86397a"
        fingerprint = "25cd85e8e65362a993a314f2fc500266fce2f343d21a2e91b146dafbbe8186db"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "0d2ce3891851808fb36779a348a83bf4aa9de1a2b2684fd0692434682afac5ec"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 5C 87 5C 24 04 89 5C 24 04 8B 1C 24 8D 64 24 04 8B 00 8B F6 87 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_f412e4b4 {
    meta:
        author = "Elastic Security"
        id = "f412e4b4-adec-4011-b4b5-f5bb77b65d84"
        fingerprint = "deb9f80d032c4b3c591935c474523fd6912d7bd2c4f498ec772991504720e683"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "0e3a3f7973f747fcb23c72289116659c7f158c604d937d6ca7302fbab71851e9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 04 C1 E2 05 8B C0 03 C2 9C 83 C5 0F 9D 8D 6D F1 05 0C 00 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_71f8e26c {
    meta:
        author = "Elastic Security"
        id = "71f8e26c-d0ff-49e8-9c20-8df9149e8843"
        fingerprint = "dbd1275bd01fb08342e60cb0c20adaf42971ed6ee0f679fedec9bc6967ecc015"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "13f873f83b84a0d38eb3437102f174f24a0ad3c5a53b83f0ee51c62c29fb1465"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 8D 64 24 04 1B 07 87 DA 8B 5D F4 52 87 DA 5B 83 C2 03 52 8B 54 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_1a562d3b {
    meta:
        author = "Elastic Security"
        id = "1a562d3b-bc59-4cb7-9ac1-7a4a79232869"
        fingerprint = "e052e99f15f5a0f704c04cae412cf4b1f01a8ee6e4ce880aedc79cf5aee9631a"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "15731db615b32c49c34f41fe84944eeaf2fc79dafaaa9ad6bf1b07d26482f055"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F0 87 1C 24 91 8D 64 24 FC 89 0C 24 8B C8 8B 04 24 87 D1 8D 64 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_410256ac {
    meta:
        author = "Elastic Security"
        id = "410256ac-fc7d-47f1-b7b8-82f1ee9f2bfb"
        fingerprint = "aa7f1d915e55c3ef178565ed12668ddd71bf3e982dba1f2436c98cceef2c376d"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "15f44e10ece90dec1a6104d5be1effefa17614d9f0cfb2784305dab85367b741"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 04 87 CA 8B 4D 0C 52 87 CA 59 03 D1 55 8B EC C9 6A 08 F7 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_93fa87f1 {
    meta:
        author = "Elastic Security"
        id = "93fa87f1-ec9d-4b3b-9c9a-a0b80963f41f"
        fingerprint = "3b53e54dfea89258a116dcdf4dde0b6ad583aff08d626c02a6f1bf0c76164ac7"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "165b4a28fd6335d4e4dfefb6c40f41f16d8c7d9ab0941ccd23e36cda931f715e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 03 87 44 24 04 89 44 24 04 8B 04 24 8D 64 24 04 8B 00 9C 83 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_8677dca3 {
    meta:
        author = "Elastic Security"
        id = "8677dca3-e36b-439f-bc55-76d951114020"
        fingerprint = "4d276b225f412b3879db19546c09d1dea2ee417c61ab6942c411bc392fee8e26"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "23813dc4aa56683e1426e5823adc3aab854469c9c0f3ec1a3fad40fa906929f2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F2 5E 83 C2 03 8B FF C1 E2 05 9C 83 C5 69 9D 8D 6D 97 03 C2 56 8B 74 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_ebce4304 {
    meta:
        author = "Elastic Security"
        id = "ebce4304-0a06-454f-ad08-98b323e5b23a"
        fingerprint = "20f0346bf021e3d2a0e25bbb3ed5b9c0a45798d0d5b2516b679f7bf17d1b040d"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "2e06caf864595f2df7f6936bb1ccaa1e0cae325aee8659ee283b2857e6ef1e5b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 8D 64 24 04 87 54 24 00 56 8B 74 24 04 5E 9D 9C 83 C5 1E 9D 8D }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_073e6161 {
    meta:
        author = "Elastic Security"
        id = "073e6161-35a3-4e5e-a310-8cc50cb28edf"
        fingerprint = "12d04597fd60ed143a1b256889eefee1f5a8c77f4f300e72743e3cfa98ba8e99"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "2e06caf864595f2df7f6936bb1ccaa1e0cae325aee8659ee283b2857e6ef1e5b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F9 83 F8 1F 77 33 80 BC 35 B9 FF FF FF 63 76 29 8B 44 24 14 40 8D }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_bef22375 {
    meta:
        author = "Elastic Security"
        id = "bef22375-0a71-4f5b-bfd1-e2e718b5c36f"
        fingerprint = "0128e8725a0949dd23c23addc1158d28c334cfb040aad2b8f8d58f39720c41ef"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "f47baf48deb71910716beab9da1b1e24dc6de9575963e238735b6bcedfe73122"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C5 35 9D 8D 6D CB 8B 12 9C 83 C5 17 9D 8D 6D E9 6A 04 F7 14 24 FF }
    condition:
        all of them
}

rule Uptycs_Ransomware_RTM_Locker {
    meta:
        malware_name = "RANSOMWARE"
        description = "Ransomware is a malware that encrypts sensitive information on your system and asks for ransom in exchange for restoring the encrypted data."
        author = "Uptycs Inc"
        version = "1"
    strings:
        $Ransomware_RTM_Locker_0 = "esxcli vm process list"  ascii wide
        $Ransomware_RTM_Locker_1 = "vmlist.tmp.txt"  ascii wide
        $Ransomware_RTM_Locker_2 = "esxcli vm process kill"  ascii wide
        $Ransomware_RTM_Locker_3 = "!!! Warning!!!"  ascii wide
        $Ransomware_RTM_Locker_4 = "Your network is infected by the RTM Locker command"  ascii wide
    condition:
        all of ($Ransomware_RTM_Locker*)
}

rule sliver_binary_native {
    meta:
        author = "Kev Breen @kevthehermit"
        description = "Detects unmodified Sliver implant generated for Windows, Linux or MacOS"
    strings: 
        $sliverpb = "sliverpb"
        $bishop_git = "github.com/bishopfox/"
        $encryption = "chacha20poly1305"
    condition:
        // This detects Go Headers for PE, ELF, Macho
        (
            (uint16(0) == 0x5a4d) or 
            (uint32(0)==0x464c457f) or 
            (uint32(0) == 0xfeedfacf) or 
            (uint32(0) == 0xcffaedfe) or 
            (uint32(0) == 0xfeedface) or 
            (uint32(0) == 0xcefaedfe) 
        )
        // String matches
        and $sliverpb
        and $bishop_git
        and $encryption
}

rule sliver_memory {
    meta:
        author = "Kev Breen @kevthehermit"
        description = "Detects Sliver running in memory"
    strings:
        $str1 = "sliverpb"
    condition:
        all of them
}

rule Doki_Attack {
    meta:
        copyright = "Intezer Labs"
        author = "Intezer Labs"
        reference = "https://www.intezer.com"
    strings:
        $a1 = /curl --retry 3 -m 60 -o \/tmp\w{6}\/tmp\/tmp.{37}.*\\{3}\"http:\/{2}.*\.ngrok\.io[\s\S]*\\{3}\";/ nocase
        $a2 = /rm -rf \/tmp\w{6}\/etc\/crontab;/ nocase
        $s1 = /echo \\{3}\"(\*\s){4}\* root sh \/tmp\/tmp.*\\{3}\" \\{2}u003e\/tmp\w{6}\/etc\/cron.d\/1m;/ nocase
        $s2 = /echo \\{3}\"(\*\s){4}\* root sh \/tmp\/tmp\w*\\{3}\" \\{2}u003e\/tmp\w{6}\/etc\/crontab;/ nocase
        $s3 = /chroot \/tmp\w{6} sh -c \\{3}\"cron \|\| crond/ nocase
    condition:
       all of them
}

rule onimiki {
  meta:
    description = "Linux/Onimiki malicious DNS server"
    malware = "Linux/Onimiki"
    operation = "Windigo"
    author = "Olivier Bilodeau <bilodeau@eset.com>"
    created = "2014-02-06"
    reference = "http://www.welivesecurity.com/wp-content/uploads/2014/03/operation_windigo.pdf"
    contact = "windigo@eset.sk"
    source = "https://github.com/eset/malware-ioc/"
    license = "BSD 2-Clause"
  strings:
    // code from offset: 0x46CBCD
    $a1 = {43 0F B6 74 2A 0E 43 0F  B6 0C 2A 8D 7C 3D 00 8D}
    $a2 = {74 35 00 8D 4C 0D 00 89  F8 41 F7 E3 89 F8 29 D0}
    $a3 = {D1 E8 01 C2 89 F0 C1 EA  04 44 8D 0C 92 46 8D 0C}
    $a4 = {8A 41 F7 E3 89 F0 44 29  CF 29 D0 D1 E8 01 C2 89}
    $a5 = {C8 C1 EA 04 44 8D 04 92  46 8D 04 82 41 F7 E3 89}
    $a6 = {C8 44 29 C6 29 D0 D1 E8  01 C2 C1 EA 04 8D 04 92}
    $a7 = {8D 04 82 29 C1 42 0F B6  04 21 42 88 84 14 C0 01}
    $a8 = {00 00 42 0F B6 04 27 43  88 04 32 42 0F B6 04 26}
    $a9 = {42 88 84 14 A0 01 00 00  49 83 C2 01 49 83 FA 07}
  condition:
    all of them
}

rule IPStorm {
    meta:
        copyright = "Intezer Labs"
        author = "Intezer Labs"
        reference = "https://www.intezer.com"
    strings:
        $package1 = "storm/backshell"
        $package2 = "storm/filetransfer"
        $package3 = "storm/scan_tools"
        $package4 = "storm/malware-guard"
        $package5 = "storm/avbypass"
        $package6 = "storm/powershell"
        $lib2b = "libp2p/go-libp2p"
    condition:
        4 of ($package*) and $lib2b
}

rule MALWARE_Linux_HiddenWasp {
    meta:
        author = "ditekSHen"
        description = "HiddenWasp backdoor payload"
        clamav_sig1 = "MALWARE_Linux.Trojan.HiddenWasp-ELF"
        clamav_sig2 = "MALWARE_Linux.Trojan.HiddenWasp-Script"
    strings:
        $x1 = "I_AM_HIDDEN" fullword ascii
        $x2 = "HIDE_THIS_SHELL" fullword ascii
        $x3 = "NewUploadFile" ascii
        $x4 = "fake_processname" ascii
        $x5 = "swapPayload" ascii
        $x6 = /Trojan-(Platform|Machine|Hostname|OSersion)/ fullword ascii
        $s1 = "FileOpration::GetFileData" fullword ascii
        $s2 = "FileOpration::NewUploadFile" fullword ascii
        $s3 = "Connection::writeBlock" fullword ascii
        $s4 = /hiding_(hidefile|enable_logging|hideproc|makeroot)/ fullword ascii
        $s5 = "Reverse-Port" fullword ascii
        $s6 = "hidden_services" fullword ascii
        $s7 = "check_config" fullword ascii
        $s8 = "__data_start" fullword ascii
        $s9 = /patch_(suger_lib|ld|lib)/ fullword ascii
        $s10 = "hexdump -ve '1/1 \"%%.2X\"' %s | sed \"s/%s/%s/g\" | xxd -r -p > %s.tmp"
    condition:
        uint16(0) == 0x457f and (4 of ($x*) or all of ($s*) or (3 of ($x*) and 5 of ($s*)))
}

rule MALWARE_Linux_Kinsing {
    meta:
      author = "ditekSHen"
      description = "Kinsing RAT payload"
    strings:
      $s1 = "backconnect" ascii
      $s2 = "connectForSocks" ascii
      $s3 = "downloadAndExecute" ascii
      $s4 = "download_and_exec" ascii
      $s5 = "masscan" ascii
      $s6 = "UpdateCommand:" ascii
      $s7 = "exec_out" ascii
      $s8 = "doTask with type %s" ascii
   condition:
      uint16(0) == 0x457f and 6 of them
}

rule MALWARE_Linux_PLEAD {
    meta:
        author = "ditekSHen"
        description = "PLEAD Linux payload"
        clamav_sig = "MALWARE.Linux.Trojan.PLEAD"
    strings:
        $x1 = "CFileTransfer" ascii
        $x2 = "CFileManager" ascii
        $x3 = "CPortForward" ascii
        $x4 = "CPortForwardManager" ascii
        $x5 = "CRemoteShell" ascii
        $x6 = "CSockClient" ascii

        $s1 = "/proc/self/exe" fullword ascii
        $s2 = "/bin/sh" fullword ascii
        $s3 = "echo -e '" ascii
        $s4 = "%s    <DIR>    %s" ascii
        $s5 = "%s    %lld    %s" ascii
        $s6 = "Files: %d        Size: %lld" ascii
        $s7 = "Dirs: %d" ascii
        $s8 = "%s(%s)/" ascii
        $s9 = "%s %s %s %s" ascii
    condition:
    uint16(0) == 0x457f and (all of ($x*) or all of ($s*) or 12 of them)
}

rule MALWARE_Linux_UNK01 {
    meta:
        author = "ditekSHen"
        description = "Detects unknown/unidentified Linux malware"
    strings:
        $f1 = "%sresponse.php?status" ascii
        $f2 = "%supstream.php?mid=%s&os=%s" ascii fullword
        $f3 = "%supstream.php?tid=%" ascii
        $f4 = "%sindex.php?token=%.32s&flag=%d&name=%s" ascii fullword
        $f5 = "%sactive_off.php?id=%d&uniqu=%d" ascii fullword
        $s1 = "lock:%i usable num:%i n:%i" fullword ascii
        $s2 = "tid:%.*s tNumber:%i" fullword ascii
        $s3 = "init.php" fullword ascii
        $s4 = "mod_drone" fullword ascii
        $s5 = "new_mid" fullword ascii
        $s6 = "&exists[]=" fullword ascii
        $s7 = "&mod[]=" fullword ascii
        $s8 = "shutdown" fullword ascii
        $s9 = "&mac[]=%02X%02X%02X%02X%02X%02X" fullword ascii
    condition:
        uint16(0) == 0x457f and (3 of ($f*) or 6 of ($s*))
}

rule MALWARE_Linux_UNK02 {
    meta:
        author = "ditekSHen"
        description = "Detects unknown/unidentified Linux malware"
    strings:
        $rf1 = "[]A\\A]A^A_" ascii
        $rf2 = "[A\\A]A^A_]" ascii
        $f1 = "/bin/basH" ascii fullword
        $f2 = "/proc/seH" ascii fullword
        $f3 = "/dev/ptsH" ascii fullword
        $f4 = "pqrstuvwxyzabcde" ascii fullword
        $f5 = "libnss_%s.so.%d.%d" ascii fullword
    condition:
        uint16(0) == 0x457f and (all of ($f*) and #rf1 > 3 and #rf2 > 3)
}

rule MALWARE_Linux_RansomExx {
    meta:
        author = "ditekshen"
        description = "Detects RansomEXX ransomware"
        clamav_sig = "MALWARE.Linux.Ransomware.RansomEXX"
    strings:
        $c1 = "crtstuff.c" fullword ascii
        $c2 = "cryptor.c" fullword ascii
        $c3 = "ransomware.c" fullword ascii
        $c4 = "logic.c" fullword ascii
        $c5 = "enum_files.c" fullword ascii
        $c6 = "readme.c" fullword ascii
        $c7 = "ctr_drbg.c" fullword ascii
        $s1 = "regenerate_pre_data" fullword ascii
        $s2 = "g_RansomHeader" fullword ascii
        $s3 = "CryptOneBlock" fullword ascii
        $s4 = "RansomLogic" fullword ascii
        $s5 = "CryptOneFile" fullword ascii
        $s6 = "encrypt_worker" fullword ascii
        $s7 = "list_dir" fullword ascii
        $s8 = "ctr_drbg_update_internal" fullword ascii
    condition:
        uint16(0) == 0x457f and (5 of ($s*) or 6 of ($s*) or (3 of ($c*) and 3 of ($s*)))
}

rule MALWARE_Linux_HelloKitty {
    meta:
        author = "ditekSHen"
        description = "Detects Linux version of HelloKitty ransomware"
    strings:
        $s1 = "exec_pipe:%s" ascii
        $s2 = "Error InitAPI !!!" fullword ascii
        $s3 = "No Files Found !!!" fullword ascii
        $s4 = "Error open log File:%s" fullword ascii
        $s5 = "%ld - Files Found  " fullword ascii
        $s6 = "Total VM run on host:" fullword ascii
        $s7 = "error:%d open:%s" fullword ascii
        $s8 = "work.log" fullword ascii
        $s9 = "esxcli vm process kill" ascii
        $s10 = "readdir64" fullword ascii
        $s11 = "%s_%d.block" fullword ascii
        $s12 = "EVP_EncryptFinal_ex" fullword ascii
        $s13 = ".README_TO_RESTORE" fullword ascii
        $m1 = "COMPROMISED AND YOUR SENSITIVE PRIVATE INFORMATION WAS STOLEN" ascii nocase
        $m2 = "damage them without special software" ascii nocase
        $m3 = "leaking or being sold" ascii nocase
        $m4 = "Data will be Published and/or Sold" ascii nocase
    condition:
        uint16(0) == 0x457f and (6 of ($s*) or (2 of ($m*) and 2 of ($s*)) or 8 of them)
}

rule APT_MAL_LNX_Turla_Apr202004_1 { 
   meta:
      description = "Detects Turla Linux malware x64 x32"
      date = "2020-04-24"
      author = "Leonardo S.p.A."
      reference = "https://www.leonardocompany.com/en/news-and-stories-detail/-/detail/knowledge-the-basis-of-protection"
      hash1 = "67d9556c695ef6c51abf6fbab17acb3466e3149cf4d20cb64d6d34dc969b6502" 
      hash2 = "8ccc081d4940c5d8aa6b782c16ed82528c0885bbb08210a8d0a8c519c54215bc" 
      hash3 = "8856a68d95e4e79301779770a83e3fad8f122b849a9e9e31cfe06bf3418fa667" 
      hash4 = "1d5e4466a6c5723cd30caf8b1c3d33d1a3d4c94c25e2ebe186c02b8b41daf905" 
      hash5 = "2dabb2c5c04da560a6b56dbaa565d1eab8189d1fa4a85557a22157877065ea08" 
      hash6 = "3e138e4e34c6eed3506efc7c805fce19af13bd62aeb35544f81f111e83b5d0d4" 
      hash7 = "5a204263cac112318cd162f1c372437abf7f2092902b05e943e8784869629dd8" 
      hash8 = "8856a68d95e4e79301779770a83e3fad8f122b849a9e9e31cfe06bf3418fa667" 
      hash9 = "d49690ccb82ff9d42d3ee9d7da693fd7d302734562de088e9298413d56b86ed0"
   strings: 
      $ = "/root/.hsperfdata" ascii fullword
      $ = "Desc| Filename | size |state|" ascii fullword
      $ = "VS filesystem: %s" ascii fullword
      $ = "File already exist on remote filesystem !" ascii fullword 
      $ = "/tmp/.sync.pid" ascii fullword
      $ = "rem_fd: ssl " ascii fullword
      $ = "TREX_PID=%u" ascii fullword
      $ = "/tmp/.xdfg" ascii fullword
      $ = "__we_are_happy__" ascii
      $ = "/root/.sess" ascii fullword
      /* $ = "ZYSZLRTS^Z@@NM@@G_Y_FE" ascii fullword */
   condition:
      uint16(0) == 0x457f and filesize < 5000KB and
      4 of them
}

rule APT_MAL_LNX_Turla_Apr202004_1_opcode { 
   meta:
      description = "Detects Turla Linux malware x64 x32"
      date = "2020-04-24"
      author = "Leonardo S.p.A."
      reference = "https://www.leonardocompany.com/en/news-and-stories-detail/-/detail/knowledge-the-basis-of-protection"
      hash1 = "67d9556c695ef6c51abf6fbab17acb3466e3149cf4d20cb64d6d34dc969b6502" 
      hash2 = "8ccc081d4940c5d8aa6b782c16ed82528c0885bbb08210a8d0a8c519c54215bc" 
      hash3 = "8856a68d95e4e79301779770a83e3fad8f122b849a9e9e31cfe06bf3418fa667" 
      hash4 = "1d5e4466a6c5723cd30caf8b1c3d33d1a3d4c94c25e2ebe186c02b8b41daf905" 
      hash5 = "2dabb2c5c04da560a6b56dbaa565d1eab8189d1fa4a85557a22157877065ea08" 
      hash6 = "3e138e4e34c6eed3506efc7c805fce19af13bd62aeb35544f81f111e83b5d0d4" 
      hash7 = "5a204263cac112318cd162f1c372437abf7f2092902b05e943e8784869629dd8" 
      hash8 = "8856a68d95e4e79301779770a83e3fad8f122b849a9e9e31cfe06bf3418fa667" 
      hash9 = "d49690ccb82ff9d42d3ee9d7da693fd7d302734562de088e9298413d56b86ed0"
   strings:
      $op0 = { 8D 41 05 32 06 48 FF C6 88 81 E0 80 69 00 } /* Xor string loop_p1 x32*/ 
      $op1 = { 48FFC14883F94975E9 } /*Xorstringloop_p2x32*/
      $op2 = { C7 05 9B 7D 29 00 1D 00 00 00 C7 05 2D 7B 29 00 65 74 68 30 C6 05 2A 7B 29 00 00 E8 }
      /* Load eth0 interface*/
      $op3 = { BF FF FF FF FF E8 96 9D 0A 00 90 90 90 90 90 90 90 90 90 90 89 F0}
      /* Opcode exceptions*/ 
      $op4 = { 88D380C305329AC1D60C08889A60A10F084283FA0876E9 }
      /* Xor string loop x64*/
      $op5 = { 8B 8D 50 DF FF FF B8 09 00 00 00 89 44 24 04 89 0C 24 E8 DD E5 02 00 } /* Kill call x32 */ 
      $op6 = { 8D 5A 05 32 9A 60 26 0C 08 88 9A 20 F4 0E 08 42 83 FA 48 76 EB } /* Decrypt init str */ 
      $op7 = { 8D 4A 05 32 8A 25 26 0C 08 88 8A 20 F4 0E 08 42 83 FA 08 76 EB} /* Decrypt init str */
   condition:
      uint16(0) == 0x457f and filesize < 5000KB and
      2 of them
}

rule Stairwell_ChamelDoH_01 {
    meta:
        author = "Daniel Mayer (daniel@stairwell.com)"
        copyright = "(c) 2023 Stairwell, Inc."
        description = "Unique strings from a sample of ChamelDoH"
        last_modified = "2023-06-07"
        version = "0.1"

    strings:
        $ = "001020304050607080910111213141516171819202122232425262728293031"
        $ = "resolve?type=TXT&name="
        $ = "CONNECT_ONLY is required!"
        $ = "[\"ns"
        $ = "touch -r"

    condition:
        4 of them
}

rule CISA_10454006_01 : SUBMARINE trojan backdoor remote_access_trojan remote_access information_gathering exploitation determines_c2_server controls_local_machine compromises_data_integrity
{
   meta:
       Author = "CISA Code & Media Analysis"
       Incident = "10452108"
       Date = "2023-06-29"
       Last_Modified = "20230711_1500"
       Actor = "n/a"
       Family = "SUBMARINE"
       Capabilities = "determines-c2-server controls-local-machine compromises-data-integrity"
       Malware_Type = "trojan backdoor remote-access-trojan"
       Tool_Type = "remote-access information-gathering exploitation"
       Description = "Detects SUBMARINE Barracuda backdoor samples"
       SHA256_1 = "81cf3b162a4fe1f1b916021ec652ade4a14df808021eeb9f7c81c8d2326bddab"
   strings:
       $s1 = { 32 35 30 2d 6d 61 69 6c 32 2e 65 63 63 65 6e 74 72 69 63 2e 64 75 63 6b }
       $s2 = { 6f 70 65 6e 73 73 6c 20 61 65 73 2d 32 35 36 }
       $s3 = { 65 63 68 6f 20 2d 6e 20 27 25 73 27 20 7c 20 62 61 73 65 36 34 20 2d 64 }
       $s4 = { 2d 69 76 }
       $s5 = { 48 65 6c 6c 6f 20 25 73 20 5b 25 73 5d 2c 20 70 6c 65 61 73 65 64 20 74 6f 20 6d 65 65 74 20 79 6f 75 }
       $s6 = { e8 47 fa ff }
       $s7 = { 63 6f 6d 6d 61 6e 64 }
       $s8 = { 2d 69 76 20 36 39 38 32 32 62 36 63 }
       $s9 = { 73 65 6e 64 }
       $s10 = { 73 6f 63 6B 65 74 }
       $s11 = { 63 6f 6e 6e 65 63 74 }
   condition:
       filesize < 15KB and 8 of them
}

rule CISA_10454006_05 : SUBMARINE trojan backdoor remote_access_trojan compromises_data_integrity cleans_traces_of_infection hides_artifacts installs_other_components remote_access exploitation
{
   meta:
       Author = "CISA Code & Media Analysis"
       Incident = "10454006"
       Date = "2023-07-05"
       Last_Modified = "20230711_1500"
       Actor = "n/a"
       Family = "SUBMARINE"
       Capabilities = "compromises-data-integrity cleans-traces-of-infection hides-artifacts installs-other-components"
       Malware_Type = "trojan backdoor remote-access-trojan"
       Tool_Type = "remote-access exploitation"
       Description = "Detects SUBMARINE launcher script samples"
       SHA256_1 = "cc131dd1976a47ee3b631a136c3224a138716e9053e04d8bea3ee2e2c5de451a"
   strings:
       $s1 = { 4c 44 5f 50 52 45 4c 4f 41 44 }
       $s2 = { 23 21 20 2f 62 69 6e 2f 73 68 }
       $s3 = { 4c 44 5f 50 52 45 4c 4f 41 44 3d 2f 62 6f 6f 74 2f 6f 73 5f 74 6f 6f 6c 73 2f 6c 69 62 75 74 69 6c 2e 73 6f 20 65 78 65 63 }
       $s4 = { 3e 2f 64 65 76 2f 6e 75 6c 6c 20 32 3e 26 31 }
       $s5 = { 62 73 6d 74 70 64 20 63 6f 6e 74 72 6f 6c 20 73 63 72 69 70 74 }
       $s6 = { 42 53 4d 54 50 44 5f 50 49 44 }
       $s7 = { 2f 72 65 6c 6f 61 64 2f 72 65 73 74 61 72 74 }
   condition:
       filesize < 6KB and 6 of them
}

rule CISA_10454006_04 : SUBMARINE trojan backdoor hides_artifacts hides_executing_code infects_files installs_other_components remote_access exploitation
{
   meta:
       Author = "CISA Code & Media Analysis"
       Incident = "10454006"
       Date = "2023-07-05"
       Last_Modified = "20230711_1500"
       Actor = "n/a"
       Family = "SUBMARINE"
       Capabilities = "hides-artifacts hides-executing-code infects-files installs-other-components"
       Malware_Type = "trojan backdoor"
       Tool_Type = "remote-access exploitation"
       Description = "Detects SUBMARINE launcher script samples"
       SHA256_1 = "b98f8989e8706380f779bfd464f3dea87c122651a7a6d06a994d9a4758e12e43"
   strings:
       $s1 = { 73 6c 65 65 70 }
       $s2 = { 7c 62 61 73 65 36 34 20 2d 64 }
       $s3 = { 4c 44 5f 50 52 45 4c 4f 41 44 }
       $s4 = { 2f 68 6f 6d 65 2f 70 72 6f 64 75 63 74 2f 63 6f 64 65 2f 66 69 72 6d 77 61 72 65 2f 63 75 72 72 65 6e 74 2f 73 62 69 6e 2f 73 6d 74 70 63 74 6c 20 72 65 73 74 61 72 74 }
       $s5 = { 65 63 68 6f 20 2d 6e 20 27 }
       $s6 = { 73 68 }
       $s7 = { 23 21 20 2f 62 69 6e 2f 73 68 }
   condition:
       filesize < 2KB and 6 of them
}

rule CISA_10454006_03 : SUBMARINE trojan backdoor loader rootkit virus controls_local_machine hides_artifacts infects_files installs_other_components remote_access exploitation information_gathering
{
   meta:
       Author = "CISA Code & Media Analysis"
       Incident = "10454006"
       Date = "2023-07-03"
       Last_Modified = "20230711_1500"
       Actor = "n/a"
       Family = "SUBMARINE"
       Capabilities = "controls-local-machine hides-artifacts infects-files installs-other-components"
       Malware_Type = "trojan backdoor loader rootkit virus"
       Tool_Type = "remote-access exploitation information-gathering"
       Description = "Detects SUBMARINE launcher script samples"
       SHA256_1 = "bbbae0455f8c98cc955487125a791052353456c8f652ddee14f452415c0b235a"
   strings:
       $s1 = { 73 65 64 20 2d 69 }
       $s2 = { 4c 44 5f 50 52 45 4c 4f 41 44 3d }
       $s3 = { 6c 69 62 75 74 69 6c 2e 73 6f }
       $s4 = { 2f 73 62 69 6e 2f 73 6d 74 70 63 74 6c }
       $s5 = { 2f 62 6f 6f 74 2f 6f 73 5f 74 6f 6f 6c 73 }
       $s6 = { 72 6d 20 2d 72 66 }
       $s7 = { 62 61 73 65 36 34 20 2d 64 }
       $s8 = { 7c 73 68 }
       $s9 = { 72 65 73 74 61 72 74 }
       $s10 = { 2f 64 65 76 2f 6e 75 6c 6c }
       $s11 = { 23 21 20 2f 62 69 6e 2f 73 68 }
       $s12 = { 62 61 73 65 36 34 }
   condition:
       filesize < 2KB and all of them
}

rule CISA_10454006_02 : SUBMARINE trojan backdoor exploitation hides_artifacts prevents_artifact_access
{
   meta:
       Author = "CISA Code & Media Analysis"
       Incident = "10454006"
       Date = "2023-06-29"
       Last_Modified = "20230711_1500"
       Actor = "n/a"
       Family = "SUBMARINE"
       Capabilities = "hides-artifacts prevents-artifact-access"
       Malware_Type = "trojan backdoor"
       Tool_Type = "exploitation"
       Description = "Detects encoded GZIP archive samples"
       SHA256_1 = "6dd8de093e391da96070a978209ebdf9d807e05c89dba13971be5aea2e1251d0"
   strings:
       $s1 = { 48 34 73 49 41 41 41 41 41 41 41 41 41 2b 30 61 }
       $s2 = { 44 44 44 41 67 50 39 2f 2b 43 38 47 70 2f 36 63 41 46 41 41 41 41 3d 3d 0a}
       $s3 = { 37 56 4d 70 56 58 4f 37 2b 6d 4c 39 78 2b 50 59 }
   condition:
       filesize < 6KB and 3 of them and (math.entropy(0,filesize) > 5.8)
}

rule CISA_10454006_07 : SUBMARINE trojan dropper exploit_kit evades_av hides_executing_code hides_artifacts exploitation
{
   meta:
       Author = "CISA Code & Media Analysis"
       Incident = "10454006"
       Date = "2023-07-11"
       Last_Modified = "20230711_1830"
       Actor = "n/a"
       Family = "SUBMARINE"
       Capabilities = "evades-av hides-executing-code hides-artifacts"
       Malware_Type = "trojan dropper exploit-kit"
       Tool_Type = "exploitation"
       Description = "Detects ESG FileName exploit samples"
       SHA256 = "8695945155d3a87a5733d31bf0f4c897e133381175e1a3cdc8c73d9e38640239"
   strings:
       $s1 = { 7c 20 62 61 73 65 36 34 20 2d 64 20 7c 20 73 68 }
       $s2 = { 65 63 68 6f 20 2d 6e }
       $s3 = { 59 32 46 30 49 43 39 32 59 58 49 76 64 47 31 77 4c 33 49 67 66 43 42 69 59 58 4e 6c 4e 6a 51 67 4c 57 51 67 4c 57 6b 67 66 43 42 30 59 58 49 67 }
   condition:
       filesize < 1KB and all of them
}

rule CISA_10454006_06 : SUBMARINE trojan backdoor cleans_traces_of_infection hides_artifacts installs_other_components
{
   meta:
       Author = "CISA Code & Media Analysis"
       Incident = "10454006"
       Date = "2023-07-11"
       Last_Modified = "20230727_1200"
       Actor = "n/a"
       Family = "SUBMARINE"
       Capabilities = "cleans-traces-of-infection hides-artifacts installs-other-components"
       Malware_Type = "trojan backdoor"
       Tool_Type = "unknown"
       Description = "Detects SUBMARINE SQL trigger samples"
       SHA256_1 = "2a353e9c250e5ea905fa59d33faeaaa197d17b4a4785456133aab5dbc1d1d5d5"
   strings:
       $s1 = { 54 52 49 47 47 45 52 }
       $s2 = { 43 52 45 41 54 45 }
       $s3 = { 53 45 4c 45 43 54 20 22 65 63 68 6f 20 2d 6e }
       $s4 = { 62 61 73 65 36 34 20 2d 64 20 7c 20 73 68 }
       $s5 = { 72 6f 6f 74 }
       $s6 = { 53 45 54 }
       $s7 = { 45 4e 44 20 49 46 3b }
       $s8 = { 48 34 73 49 41 41 41 41 41 41 41 41 41 2b 30 61 43 33 42 55 }
       $s9 = { 2f 76 61 72 2f 74 6d 70 2f 72 }
       $s10 = { 2f 72 6f 6f 74 2f 6d 61 63 68 69 6e 65 }
   condition:
   filesize < 250KB and all of them
}

rule EXIM_CVE_2019_10149 {
meta:
    description = "Yara Rule EXIM UPX and de-UPX"
    author = "Cybaze - Yoroi ZLab"
    last_updated = "2019-06-19"
    tlp = "white"
    category = "informational"
strings:
    $s1 = "ELF"
    $s2 = "Buildroot 2014.02"
    $s3 = "445403338652341"
    $s4 = {96 0E 14 41 C3 0E 10 44 C6}
    $s5 = {5C 24 0C 01 E9 8A 0C 01 32 4C}  
    $s6 = "OpenSSL 1.0.1f 6 Jan 2014"  
    $s7 = {0E 14 41 C3 0E 10}
    $s8 = {5E CC 14 D8 E1 48 BF 7E 6D}
    $s9 = {FF 83 A7 24 01 00 00 FD}
    $s10 = "UWVSQ"
    $s11 = {C1 0A CF 0A D9 0A E5}
    $a12 = "UPX"
    $a13 = {22 00 1A 03 00 2A A2}
    $a14 = {55 06 3C 3C BA 4D E9 C6}
    $a15 = {0B 58 A6 9E 88 BD 51 C1 22}
    $a16 = {67 2A 21 57 23 3B 29}
    $a17 = {F5 6F D7 CD 6D 28 1F 49}
    $a18 = {66 FA A4 B5 78 F0 24 C3}
    $a19 = {8E 82 07 8D 05 53 80 29}
    $a20 = {9B 1C B7 E4 57 93 35 8F 7A}
    $a21 = {47 8F 7E 4D 0B 24 8C 7D}
condition:
    $s1 and 4 of ($s*) or $s1 and 5 of ($a*)
}

rule derusbi_kernel {
    meta:
        description = "Derusbi Driver version"
        date = "2015-12-09"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Fabien Perigaud"
    strings:
        $token1 = "$$$--Hello"     
        $token2 = "Wrod--$$$"   
        $cfg = "XXXXXXXXXXXXXXX"
        $class = ".?AVPCC_BASEMOD@@"
        $MZ = "MZ"
    condition:
        $MZ at 0 and $token1 and $token2 and $cfg and $class
}

rule derusbi_linux {
    meta:
        description = "Derusbi Server Linux version"
        date = "2015-12-09"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Fabien Perigaud"
    strings:
        $PS1 = "PS1=RK# \\u@\\h:\\w \\$"
        $cmd = "unset LS_OPTIONS;uname -a"
        $pname = "[diskio]"
        $rkfile = "/tmp/.secure"
        $ELF = "\x7fELF"
    condition:
        $ELF at 0 and $PS1 and $cmd and $pname and $rkfile
}

rule BiBi_Linux_Wiper {
    meta:
        author ="Felipe Duarte, Security Joes"
        description ="Detects BiBi-Linux Wiper"
        sha256_reference ="23bae09b5699c2d5c4cb1b8aa908a3af898b00f88f06e021edcb16d7d558efad"

    strings:
        $str1 = "[+] Stats: "
        $str2 = { 2e 00 00 00 42 00 00 00 69 00 00 00 42 00 00 00 69 00 }
        $str3 = "[!] Waiting For Queue "
        $str4 = "[+] Round "
        $str5 = "[+] Path: "
        $str6 = "[+] CPU cores: " 
        $str7 = "Threads: "

    condition:
        all of them
}

rule Linux_Malware_GTPDOOR_v1v2 {
    meta:
        description = "Detects GTPDOOR"
        author = "@haxrob"
        data = "28/02/2024"
        reference = "https://doubleagent.net/telecommunications/backdoor/gtp/2024/02/27/GTPDOOR-COVERT-TELCO-BACKDOOR"
        hash1 = "827f41fc1a6f8a4c8a8575b3e2349aeaba0dfc2c9390ef1cceeef1bb85c34161"
        hash2 = "5cbafa2d562be0f5fa690f8d551cdb0bee9fc299959b749b99d44ae3fda782e4"
    strings:
        $s1 = "excute result is" ascii fullword
        $s2 = "idkey not correct" ascii fullword
        $s3 = "send ret message" ascii fullword
    condition:
        uint16(0) == 0x457f and
        2 of them and
        filesize < 20KB
}

rule libkeyutils_with_ctor {
    meta:
        description = "This rule detects if a libkeyutils.so shared library has a potentially malicious function to be called when loaded, either via a glibc constructor (DT_INIT + .ctors) or an initializer function in DT_INIT_ARRAY."
        author = "Marc-Etienne M.Léveillé <leveille@eset.com>"
        copyright = "ESET, spol. s r.o."
        license = "BSD 2-Clause"
        date = "2024-02-01"
        reference = "https://www.welivesecurity.com"
        source = "https://github.com/eset/malware-ioc/"
        hash = "e7debd6e453192ad8376db5bab03ed0d87566591"
        version = 2
        last_modified = "2024-04-29"

    strings:
        $libname = "libkeyutils.so.1"

    condition:
        for any ptr_size in (4,8): (
            (
                (ptr_size == 4 and elf.machine == elf.EM_386)
                or
                (ptr_size == 8 and elf.machine == elf.EM_X86_64)
            )
            and
            for any d in elf.dynamic: (
                d.type == elf.DT_SONAME
                and
                (
                    for any s in elf.sections: (
                        s.name == ".dynstr" and
                        $libname at (s.offset + d.val)
                    )
                    or
                    for any s in elf.dynamic: (
                        s.type == elf.DT_STRTAB and
                        $libname at (s.val + d.val)
                    )
                )
            )
            and
            (
                for any s in elf.sections: (
                    s.name == ".ctors" and s.size > 2 * ptr_size
                )
                or
                for any d in elf.dynamic: (
                    d.type == elf.DT_INIT_ARRAYSZ and d.val > ptr_size
                )
            )
        )
}

rule Ebury_v1_7_crypto {
    meta:
        description = "This rule detects the strings decryption routine in Ebury v1.7 and v1.8"
        author = "Marc-Etienne M.Léveillé <leveille@eset.com>"
        copyright = "ESET, spol. s r.o."
        license = "BSD 2-Clause"
        date = "2023-08-01"
        reference = "https://www.welivesecurity.com"
        source = "https://github.com/eset/malware-ioc/"
        hash = "e7debd6e453192ad8376db5bab03ed0d87566591"
        version = 1
        last_modified = "2024-04-29"

    strings:
        $64 = {
            48 69 ( 9C 24 ?? ?? ?? ?? | 5C 24 ?? | D2) 6D 4E C6 41 //  imul    rbx, [rsp+_buf], 41C64E6Dh
            8B (0C 16 | 34 07)                      //  mov     ecx, [rsi+rdx]
            48 81 C? 39 30 00 00                    //  add     rbx, 12345
            ( 31 D? |                               //  xor     ecx, ebx
              31 D? 48 89 9C 24 ?? ?? ?? ?? |       //  mov     [rsp+_buf], rbx
              31 D? 48 89 5C 24 ?? )                //  ^ optional
            89 (0C 10 | 34 01)                      //  mov     [rax+rdx], ecx
            48 83 C? 04                             //  add     rdx, 4
            48 (81 FA | 3D ) ?? ?? ?? ??            //  cmp     rdx, _size
            75 D?                                   //  jnz     short _begin
        }

        $32 = {
            69 C9 6D 4E C6 41      // imul    ecx, 41C64E6Dh
            8B B4 1A ?? ?? ?? ??   // mov     esi, [edx+ebx+_data]
            81 C1 39 30 00 00      // add     ecx, 12345
            31 CE                  // xor     esi, ecx
            89 34 10               // mov     [eax+edx], esi
            83 C2 04               // add     edx, 4
            81 FA ?? ?? ?? ??      // cmp     edx, _size
            75 DD                  // jnz     short loc_69A5
        }

    condition:
        any of them
}

private rule ApacheModule {
    meta:
        description = "Apache 2.4 module ELF shared library"
        author = "Marc-Etienne M.Léveillé <leveille@eset.com>"
        copyright = "ESET, spol. s r.o."
        license = "BSD 2-Clause"
        date = "2024-04-27"
        reference = "https://www.welivesecurity.com"
        source = "https://github.com/eset/malware-ioc/"
        hash = "e39667aa137e315bc26eaef791ccab52938fd809"
        version = 1
        last_modified = "2024-04-27"

    strings:
        $magic = "42PA" // 'AP24' in LE

    condition:
        for any s in elf.dynsym: (
            s.type == elf.STT_OBJECT and
            for any seg in elf.segments: (
                seg.type == elf.PT_LOAD and
                s.value >= seg.virtual_address and
                s.value < (seg.virtual_address + seg.file_size) and
                $magic at (s.value - seg.virtual_address + seg.offset) + 0x28
            )
        )
}

rule HelimodProxy {
    meta:
        description = "HelimodProxy malicious Apache module"
        author = "Marc-Etienne M.Léveillé <leveille@eset.com>"
        copyright = "ESET, spol. s r.o."
        license = "BSD 2-Clause"
        date = "2024-04-27"
        reference = "https://www.welivesecurity.com"
        source = "https://github.com/eset/malware-ioc/"
        hash = "e39667aa137e315bc26eaef791ccab52938fd809"
        version = 1
        last_modified = "2024-04-27"

    strings:
        $1 = "secret\x00%s:%u"
        $2 = "/%s/%s/%s%s"
        $3 = "ad\x00pmt"
        $4 = "mod_dir.c"
        $5 = "pmtad"
    condition:
        ApacheModule and ($1 or ($2 and $3) or ($4 and $5))
}

rule HelimodRedirect {
    meta:
        description = "HelimodRedirect malicious Apache module"
        author = "Marc-Etienne M.Léveillé <leveille@eset.com>"
        copyright = "ESET, spol. s r.o."
        license = "BSD 2-Clause"
        date = "2024-04-27"
        reference = "https://www.welivesecurity.com"
        source = "https://github.com/eset/malware-ioc/"
        hash = "e39667aa137e315bc26eaef791ccab52938fd809"
        version = 1
        last_modified = "2024-04-27"

    strings:
        $h1 = "secret\x00%s:%"
        $h2 = "$!%#!$"
        $h3 = "mod_security2.c"
        $r1 = "%s?DOM=%s&URI=%s"
        $r2 = "REDIRECT_URL"

    condition:
        ApacheModule and any of ($h*) and any of ($r*)
}

rule HelimodSteal {
    meta:
        description = "HelimodSteal malicious Apache module"
        author = "Marc-Etienne M.Léveillé <leveille@eset.com>"
        copyright = "ESET, spol. s r.o."
        license = "BSD 2-Clause"
        date = "2024-04-27"
        reference = "https://www.welivesecurity.com"
        source = "https://github.com/eset/malware-ioc/"
        hash = "e39667aa137e315bc26eaef791ccab52938fd809"
        version = 2
        last_modified = "2024-04-27"

    strings:
        $h1 = "secret\x00%s:%"
        $h2 = "$!%#!$"
        $h3 = "mod_security2.c"
        $s1 = "p0sT5n1F3r"
        $s2 = "ENGINE_ON"
        $s3 = "POST /"

    condition:
        ApacheModule and any of ($h*) and any of ($s*)
}

rule SUSP_ELF_LNX_UPX_Compressed_File {
   meta:
      description = "Detects a suspicious ELF binary with UPX compression"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-12-12"
      score = 40
      hash1 = "038ff8b2fef16f8ee9d70e6c219c5f380afe1a21761791e8cbda21fa4d09fdb4"
      id = "078937de-59b3-538e-a5c3-57f4e6050212"
   strings:
      $s1 = "PROT_EXEC|PROT_WRITE failed." fullword ascii
      $s2 = "$Id: UPX" fullword ascii
      $s3 = "$Info: This file is packed with the UPX executable packer" ascii

      $fp1 = "check your UCL installation !"
   condition:
      uint16(0) == 0x457f and filesize < 2000KB and
      filesize > 30KB and 2 of ($s*)
      and not 1 of ($fp*)
}

rule M_Sniffer_LOOKOVER_1 {
    meta:
        author = "Mandiant"
    strings:
        $str1 = "TKEY" 
        $str2 = "FILTER" 
        $str3 = "DEVICE" 
        $str4 = "SNFILENAME" 
        $str5 = "/var/lib/libsyslog.so" 
        $code = {8B 55 F8 48 8B 45 E8 48 01 C2 8B 45 FC 48 8D 0C 85 00 00 00 00 48 8B 45 E0 48 01 C8 8B 00 88 02 8B 45 F8 83 C0 01 89 C2 48 8B 45 E8 48 01 C2 8B 45 FC 48 8D 0C 85 00 00 00 00 48 8B 45 E0 48 01 C8 8B 00 C1 E8 08 88 02 8B 45 F8 83 C0 02 89 C2 48 8B 45 E8 48 01 C2 8B 45 FC 48 8D 0C 85 00 00 00 00 48 8B 45 E0 48 01 C8 8B 00 C1 E8 10 88 02 8B 45 F8 83 C0 03 89 C2 48 8B 45 E8 48 01 C2 8B 45 FC 48 8D 0C 85 00 00 00 00 48 8B 45 E0 48 01 C8 8B 00 C1 E8 18 88 02 83 45 FC 01 83 45 F8 04}
    condition:
        uint32(0) == 0x464c457f and filesize < 5MB and all of them
}

rule M_Utility_GHOSTTOWN_1 {
    meta:
        author = "Mandiant"
    strings:
        $code1 = { 2F 76 61 72 2F 6C 6F 67 } 
        $code2 = { 2F 76 61 72 2F 72 75 6E } 
        $debug1 = "=== results ===" ascii
        $debug2 = "=== %s ===" ascii
        $debug3 = "searching record in file %s" ascii
        $debug4 = "record not matched, not modifing %s" ascii
        $debug5 = "delete %d records in %s" ascii
        $debug6 = "NEVER_LOGIN" ascii
        $debug7 = "you need to specify a username to clear" ascii
        $pattern1 = "%-10s%-10s%-10s%-20s%-10s" ascii
        $pattern2 = "%-15s%-10s%-15s%-10s" ascii
    condition:
        uint32(0) == 0x464C457F and all of them
}

rule M_Utility_VIRTUALPEER_1 {
    meta:
        author = "Mandiant"
    strings:
        $vmci_socket_family = {B? 00 00 00 00 B? 02 00 00 00 B? 28 00 00 00 e8 [4-128] B? 00 00 00 00 48 8d [5] b? 00 00 00 00 e8 [4-64] B?  00 00 00 00 48 8d [5] b? 00 00 00 00 e8 [4-64] B? B8 07 00 00 [0-8] b?  00 00 00 00 e8}
        $vmci_socket_marker1 = "/dev/vsock" ascii wide
        $vmci_socket_marker2 = "/vmfs/devices/char/vsock/vsock" ascii wide
        $vmci_socket_init_bind_listen = {e8 [4] 89 45 [4-64] 8B 45 ?? b?  00 00 00 00 b? 01 00 00 00 [0-4] e8 [4-128] B? 10 00 00 00  [1-16] e8 [4-128] BE 01 00 00 00 [1-16] e8 [4] 83 F8 FF}
        $socket_read_write = {BA 01 00 00 00 48 89 CE 89 C7 E8 [4] 48 85 C0 [1-64] BA 01 00 00 00 48 89 CE 89 C7 E8 [4] 48 85 C0 7e ?? eb}
        $marker1 = "nc <port>"
    condition:
        uint32(0) == 0x464c457f and all of them
}

rule M_Hunting_VIRTUALPITA_1 {
    meta:
        author = "Mandiant"
    strings:
        $forpid = { 70 69 64 20 [0-10] 69 6E 20 60 [0-10] 70 73 20 2D [0-10] 63 20 7C 20 [0-10] 67 72 65 70 [0-10] 20 76 6D 73 [0-10] 79 73 6C 6F [0-10] 67 64 20 7C [0-10] 20 61 77 6B [0-10] 20 27 7B 20 [0-10] 70 72 69 6E [0-10] 74 20 24 31 [0-10] 20 7D 27 60 [0-10] 3B 20 64 6F [0-10] 20 6B 69 6C [0-10] 6C 20 2D 39 [0-10] 20 24 70 69 [0-10] 64 3B 20 64 [0-10] 6F 6E 65 00 }
        $vmsyslogd = { 2F 75 73 72 [0-10] 2F 6C 69 62 [0-10] 2F 76 6D 77 [0-10] 61 72 65 2F [0-10] 76 6D 73 79 [0-10] 73 6C 6F 67 [0-10] 2F 62 69 6E [0-10] 2F 76 6D 73 [0-10] 79 73 6C 6F [0-10] 67 64 00 00 }
    condition:
        uint32(0) == 0x464c457f and any of them
}

rule M_APT_Launcher_REPTILE_1 {
    meta:
        author = "Mandiant"
    strings:
        $str1 = {B8 00 00 00 00 E8 A1 FE FF FF 48 8B 85 40 FF FF FF 48 83 C0 08 48 8B 00 BE 00 00 00 00 48 89 C7 B8 00 00 00 00 E8 ??  FD FF FF 89 45 ?8 48 8D 95 50 FF FF FF 8B 45 ?8 48 89 D6 89 C7 E8 ?? 0? 00 00 48 8B 45 80 48 89 45 F0 48 8B 45 F0 48 89 C7 E8 ?? F? FF FF 48 89 45 ?8 48 8B 55 F0 48 8B 4D ?8 8B 45 ?8 48 89 CE 89 C7 E8 ?? FC FF FF 48 8B 55 F0 48 8B 45 ?8 B9 4? 0C 40 00 48 89 C6 BF AF 00 00 00 B8 00 00 00 00 E8 ?? FC FF FF E8 ?? FC FF FF 8B 00 83 F8 25 75 07 C7 45 ?C 00 00 00 00 } 
  $str2 = {81 7D F? FF 03 00 00 7E E9 BE 02 00 00 00 BF ?? 0C 40 00 B8 00 00 00 00 E8 ?? F? FF FF 89 45 F? 8B 45 F? BE 01 00 00 00 89 C7 E8 ?? FD FF FF 8B 45 F? BE 02 00 00 00 89 C7 E8 ?? F?  FF FF C9 C3} 
    condition:
        uint32(0) == 0x464C457F and all of them
}

rule M_APT_Backdoor_VIRTUALSHINE_1 {
    meta:
        author = "Mandiant"
    strings:
        $str1 = "/dev/vsock"
        $str2 = "/vmfs/devices/char/vsock/vsock"
        $str3 = "nds4961l <cid> <vport>"
        $str4 = "[!] VMCISock_GetAFValue()."
        $str5 = "[+] Connected to server.[ %s:%s ]"
        $str6 = "TERM=xterm"
        $str7 = "PWD=/tmp/"
    condition:
        uint32(0) == 0x464C457F and all of them
}

rule M_APT_BACKDOOR_MOPSLED_1 {
    meta:
        author = "Mandiant"
    strings:
        $x = { e8 ?? ?? ?? ?? 85 c0 0f 85 ?? ?? ?? ?? 4? 8d ?? ?4 ?8 be ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 0f 84 ?? ?? ?? ?? 4? 8b 94 ?? ?? ?? ??  ?? 4? 8b 44 ?? ?? 4? 89 e1 [0-6]  be ?? ?? ?? ?? b? ?? ?? ?? ?? 4? 89 10 8b 94 ?? ?? ?? ?? ?? [0-6] 89 50 08 4? 8b 54 ?? ?? c7 42 0c ?? ?? ?? ?? e8 ?? ?? ?? ?? }
    condition:
          uint32(0) == 0x464c457f and uint8(4) == 2 and filesize < 5MB and $x
}

rule P2PinfectBash {
  meta:
    author = "nbill@cadosecurity.com"
    description = "Detects P2Pinfect bash payload"
  strings:
    $h1 = { 4C 89 EF 48 89 DE 48 8D 15 ?? ?? ?? 00 6A 0A 59 E8 17 6C 01 00 84 C0 0F 85 0F 03 00 00 }
    $h2 = { 48 8B 9C 24 ?? ?? 00 00 4C 89 EF 48 89 DE 48 8D 15 ?? ?? ?? 00 6A 09 59 E8 34 6C 01 00 84 C0 0F 85 AC 02 00 00 }
    $h3 = { 4C 89 EF 48 89 DE 48 8D 15 ?? ?? ?? 00 6A 03 59 E8 DD 6B 01 00 84 C0 0F 85 DF 03 00 00 }
  condition:
    uint16(0) == 0x457f and all of them
}

rule XMRig {
   meta:
      attack = "T1496"
      description = "Detects XMRig miner"
   strings:
      $ = "password for mining server" nocase wide ascii
      $ = "threads count to initialize RandomX dataset" nocase wide ascii
      $ = "display this help and exit" nocase wide ascii
      $ = "maximum CPU threads count (in percentage) hint for autoconfig" nocase wide ascii
      $ = "enable CUDA mining backend" nocase wide ascii
      $ = "cryptonight" nocase wide ascii
   condition:
      5 of them
}

rule P2PinfectRsagen {
  meta:
    author = "nbill@cadosecurity.com"
    description = "Detects P2Pinfect rsagen payload"
  strings:
    $a1 = "$ENC_EXE$"
    $a2 = "$EMAIL_ADDRS$"
    $a3 = "$XMR_COUNT$"
    $a4 = "$XMR_ADDR$"
    $a5 = "$KEY_STR$"
    $a6 = "$ENC_DATABASE$"
    $b1 = "mdbmdfmydldfibdmyidbdbfwdbfrmaccdbsqlsqlite3msgemltxtcsv123docwpsxlsetpptppsdpsonevsdjpgpngziprar7ztarbz2tbkgztgzbakbackupdotxlwxltxlmxlcpotpubmppodtodsodpodgodfodbwpdqpwshwpdfaip64xpsrptrtfchmmhthtmurlswfdatrbaspphpjsppashcppccspyshclassjarvbvbsps1batcmdjsplsuoslnbrdschdchdipbmpgificopsdabrmaxcdrdwgdxfmbpspdgnexbjnbdcdqcdtowqxpqptsdrsdtpzfemfociiccpcbtpfgjdaniwmfvfbsldprtdbxpstdwtvalcadfabbsfccfudfftfpcfdocicaascgengcmostwkswk1onetoc2sntedbhwp602sxistivdivmxgpgaespaoisovcdrawcgmtifnefsvgm4um3umidwmaflv3g2mkv3gpmp4movaviasfvobmpgwmvflawavmp3laymmlsxmotguopstdsxdotpwb2slkdifstcsxcots3dm3dsuotstwsxwottpemp12csrcrtkeypfxder"
    $c1 = "lock failedlocked"
    $c2 = "/root/homeencrypt"
  condition:
    uint16(0) == 0x457f and (2 of ($a*) or $b1 or all of ($c*))
}

rule P2PinfectLDPreload {
  meta:
    author = "nbill@cadosecurity.com"
    description = "Detects P2Pinfect libs.so.1 payload"
  strings:
    $a1 = "env_var"
    $a2 = "main_file"
    $a3 = "hide.c"
    $b1 = "prefix"
    $b2 = "process1"
    $b3 = "process2"
    $b4 = "process3"
    $b5 = "owner"
    $c1 = "%d: [0-9A-Fa-f]:%X [0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %lu 2s"
    $c2 = "/proc/net/tcp"
    $c3 = "/proc/net/tcp6"
  condition:
    uint16(0) == 0x457f and (all of ($a*) or all of ($b*) or all of ($c*))
}

rule Kinsing_Malware {
    meta:
        author = "Aluma Lavi, CyberArk"
        date = "22-01-2021"
        version = "1.0"
        hash = "d247687e9bdb8c4189ac54d10efd29aee12ca2af78b94a693113f382619a175b"
        description = "Kinsing/NSPPS malware"
    strings:
        $rc4_key = { 37 36 34 31 35 33 34 34 36 62 36 31 }
        $firewire = "./firewire -iL $INPUT --rate $RATE -p$PORT -oL $OUTPUT"
        $packa1 = "google/btree" ascii wide
        $packa2 = "kardianos/osext" ascii wide
        $packa3 = "kelseyhightower/envconfig" ascii wide
        $packa4 = "markbates/pkger" ascii wide
        $packa5 = "nu7hatch/gouuid" ascii wide
        $packa6 = "paulbellamy/ratecounter" ascii wide
        $packa7 = "peterbourgon/diskv" ascii wide
        $func1 = "main.RC4" ascii wide
        $func2 = "main.runTaskWithScan" ascii wide
        $func3 = "main.backconnect" ascii wide
        $func4 = "main.downloadAndExecute" ascii wide
        $func5 = "main.startCmd" ascii wide
        $func6 = "main.execTaskOut" ascii wide
        $func7 = "main.minerRunningCheck" ascii wide
    condition:
        (uint16(0) == 0x457F
        and not (elf.sections[0].size + elf.sections[1].size + elf.sections[2].size + elf.sections[3].size + elf.sections[4].size + elf.sections[5].size + elf.sections[6].size + elf.sections[7].size > filesize))
        and ($rc4_key
        or $firewire
        or all of ($packa*)
        or 4 of ($func*)
    )
}

rule Detect_Base64_Obfuscation_Py {
    meta:
      description = "Detects obfuscated Python code that uses base64 decoding"
      author = "tgould@cadosecurity.com"
      date = "2024-09-04"
    strings:
      $import_base64 = "import base64" ascii
      $exec_base64_decode = "exec(base64.b64decode(" ascii
      $decode_exec = "base64.b64decode(b).decode())" ascii

    condition:
      all of ($import_base64, $exec_base64_decode, $decode_exec)
}

rule perfcc_script {
    meta:
        author = "tgould@cadosecurity.com"
        description = "Detects script used to set up and retrieve Perfcc"

    strings:
      $env = "AAZHDE"
      $dir = "mkdir /tmp/.perf.c 2>/dev/null"
      $dir_2 = "mkdir /tmp/.xdiag 2>/dev/null"
      $curl = "\"curl/7.74.9\""
      $command = "pkill -9 perfctl &>/dev/null"
      $command_2 = "killall -9 perfctl &>/dev/null"
      $command_3 = "chmod +x /tmp/httpd"

    condition:
        $env and ($dir or $dir_2) and any of ($command*) and $curl

}

rule Linux_Trojan_Pumakit {
    meta:
        author = "Elastic Security"
        creation_date = "2024-12-09"
        last_modified = "2024-12-09"
        os = "Linux"
        arch = "x86, arm64"
        threat_name = "Linux.Trojan.Pumakit"
    strings:
        $str1 = "PUMA %s"
        $str2 = "Kitsune PID %ld"
        $str3 = "/usr/share/zov_f"
        $str4 = "zarya"
        $str5 = ".puma-config"
        $str6 = "ping_interval_s"
        $str7 = "session_timeout_s"
        $str8 = "c2_timeout_s"
        $str9 = "LD_PRELOAD=/lib64/libs.so"
        $str10 = "kit_so_len"
        $str11 = "opsecurity1.art"
        $str12 = "89.23.113.204"
    condition:
        4 of them
}

rule Linux_Trojan_Winnti_61215d98 {
    meta:
        author = "Elastic Security"
        id = "61215d98-f52d-45d3-afa2-4bd25270aa99"
        fingerprint = "20ee92147edbf91447cca2ee0c47768a50ec9c7aa7d081698953d3bdc2a25320"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Winnti"
        reference_sample = "cc1455e3a479602581c1c7dc86a0e02605a3c14916b86817960397d5a2f41c31"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FF FF FF C9 C3 55 48 89 E5 48 83 EC 30 89 F8 66 89 45 DC C7 45 FC FF FF }
    condition:
        all of them
}

rule Linux_Trojan_Winnti_4c5a1865 {
    meta:
        author = "Elastic Security"
        id = "4c5a1865-ff41-445b-8616-c83b87498c2b"
        fingerprint = "685fe603e04ff123b3472293d3d83e2dc833effd1a7e6c616ff17ed61df0004c"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Winnti"
        reference = "0d963a713093fc8e5928141f5747640c9b43f3aadc8a5478c949f7ec364b28ad"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C1 E8 1F 84 C0 75 7B 85 D2 89 D5 7E 75 8B 47 0C 39 C6 7D 6E 44 8D }
    condition:
        all of them
}

rule Linux_Trojan_Winnti_6f4ca425 {
    meta:
        author = "Elastic Security"
        id = "6f4ca425-5cd2-4c22-b017-b5fc02b3abc2"
        fingerprint = "dec25af33fc004de3a1f53e0c3006ff052f7c51c95f90be323b281590da7d924"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Winnti"
        reference = "161af780209aa24845863f7a8120aa982aa811f16ec04bcd797ed165955a09c1"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 E5 48 89 7D D8 48 8B 45 D8 0F B6 40 27 0F BE C0 89 45 F8 48 8B }
    condition:
        all of them
}

rule Linux_Trojan_Winnti_de4b0f6e {
    meta:
        author = "Elastic Security"
        id = "de4b0f6e-0183-4ea8-9c03-f716a25f1884"
        fingerprint = "c72eddc2d72ea979ad4f680d060aac129f1cd61dbdf3b0b5a74f5d35a9fe69d7"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Winnti"
        reference = "a6b9b3ea19eaddd4d90e58c372c10bbe37dbfced638d167182be2c940e615710"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 85 30 FF FF FF 02 00 48 8D 85 30 FF FF FF 48 8D 50 02 0F B7 85 28 FF }
    condition:
        all of them
}

rule rootkit_lin_winnti {
    meta:
        id = "c800038e-7f8a-4f24-bf0b-06aba6a828cb"
        version = "1.0"
        description = "Rootkit used by Winnti"
        author = "Sekoia.io"
        creation_date = "2024-05-22"
        classification = "TLP:CLEAR"
        reference = "https://x.com/naumovax/status/1792902386295394629"
        hash1 = "161344ae61278e09eacb1c76508cda45555eee109e6d6a031716a096ab5c84f3"
        hash2 = "bb56e088739b281c9f56b4fa3fa4d285e45b32c4f9f06b647d7e8cb916054e1a"
        hash3 = "777c1fda4008f122ff3aef9e80b5b5720c9f2dbc3d7e708277e2ccad1afd8cc5"
        hash4 = "9c770b12a2da76c41f921f49a22d7bc6b5a1166875b9dc732bc7c05b6ae39241"

    strings:
        $ = "[CDATA[%s]]></name><type>%o</type><perm>%o</perm><user>%s:%s</user><size>%llu</size><time>%s</time></LIST>"
        $ = "HideFile"
        $ = "DownThread"
        $ = "PortforwardThread"
        $ = "HidePidPort"
        $ = "DownFile"
        $ = "ReadReConnConf"
        $ = "DecRemotePort"
        $ = "DecRemoteIP"

    condition:
        uint32(0)==0x464c457f 
        and 6 of them
        and for any i in (0..elf.number_of_sections-1) : (
            hash.md5(elf.sections[i].offset, elf.sections[i].size) == "7dea362b3fac8e00956a4952a3d4f474"
        )
}

rule Linux_Trojan_FinalDraft_4ea5a204 {
    meta:
        author = "Elastic Security"
        id = "4ea5a204-5136-42c2-80f0-634368936296"
        fingerprint = "86cc29da59c8801d7443851e2c16f04d187de9705b16cc7fca553ea09baf0eb8"
        creation_date = "2025-01-23"
        last_modified = "2025-02-04"
        threat_name = "Linux.Trojan.FinalDraft"
        reference_sample = "83406905710e52f6af35b4b3c27549a12c28a628c492429d3a411fdb2d28cc8c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str_comm_option_1 = "CBindTcpTransChannel"
        $str_comm_option_2 = "CDnsTransChannel"
        $str_comm_option_3 = "CHttpTransChannel"
        $str_comm_option_4 = "CIcmpTransChannel"
        $str_comm_option_5 = "COutLookTransChannel"
        $str_comm_option_6 = "CReverseTcpTransChannel"
        $str_comm_option_7 = "CReverseUdpTransChannel"
        $str_comm_option_8 = "CWebTransChannel"
        $str_feature_1 = "%s?type=del&id=%s" fullword
        $str_feature_2 = "client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c&grant_type=refresh_token" fullword
        $str_feature_3 = "/var/log/installlog.log.%s" fullword
        $str_feature_4 = "/mnt/hgfsdisk.log.%s" fullword
        $str_feature_5 = "%-10s %-25s %-25s %-15s" fullword
        $str_feature_6 = "%-20s %-10s %-10s %-10s %-30s" fullword
        $str_feature_7 = { 48 39 F2 74 ?? 48 0F BE 0A 48 FF C2 48 6B C0 ?? 48 01 C8 EB ?? }
    condition:
        (1 of ($str_comm_option*)) and (3 of ($str_feature_*))
}

rule Multi_Trojan_FinalDraft_81975d51 {
    meta:
        author = "Elastic Security"
        id = "81975d51-96e9-4a49-97ee-56e2c60e9702"
        fingerprint = "a2d5e2f472499ad6c5ff052eded73fa182bb20cecb9c3921f37bd779a2a77c9b"
        creation_date = "2024-12-03"
        last_modified = "2025-02-04"
        threat_name = "Multi.Trojan.FinalDraft"
        reference_sample = "fa2a6dbc83fe55df848dfcaaf3163f8aaefe0c9727b3ead1da6b9fa78b598f2b"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = "[-] socket() failed!"
        $a2 = "MailFolders/drafts/messages?$filter=Subject"
        $a3 = "{\"subject\":\"p_%llu\",\"body\":"
        $a4 = "COutLookTransChannel"
        $a5 = "CTransChannel"
        $a6 = "Chrome/40.0.2214.85 Safari/537.36"
    condition:
        3 of them
}

rule Multi_Trojan_FinalDraft_69deb8cd {
    meta:
        author = "Elastic Security"
        id = "69deb8cd-050b-4b92-86c2-ea54f836ce72"
        fingerprint = "3e48740092918896132e801ae4d850ef804f9dd6c8db96b80065224566c17819"
        creation_date = "2024-12-03"
        last_modified = "2025-02-04"
        threat_name = "Multi.Trojan.FinalDraft"
        reference_sample = "fa2a6dbc83fe55df848dfcaaf3163f8aaefe0c9727b3ead1da6b9fa78b598f2b"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = { 33 FF C7 44 24 20 3A 00 77 00 4C 8B F1 C7 44 24 24 74 00 66 00 48 83 C8 FF C7 44 24 28 62 00 62 00 C7 44 24 2C 71 00 00 00 48 8D 4C 24 20 }
        $a2 = { 48 81 EC B0 00 00 00 48 8B 05 00 5B 05 00 48 33 C4 48 89 84 24 A0 00 00 00 0F 57 C0 0F 11 44 24 48 4C 8B C2 48 8D 54 24 48 E8 00 0B 00 00 90 48 83 7C 24 50 00 0F 84 31 01 00 00 48 8B 7C 24 48 }
        $a3 = { 48 8D 7C 24 48 C6 43 40 00 48 C7 43 48 00 00 00 00 48 C7 43 50 00 00 00 00 48 89 43 68 48 8B ?? ?? ?? ?? 00 48 C7 43 58 00 00 00 00 C7 43 60 00 00 00 00 48 C7 43 70 00 00 00 00 C6 43 78 00 48 8D B0 FD 00 00 00 }
        $a4 = { 48 83 EC 58 B9 0D 00 00 00 BE 1E 00 00 00 64 48 8B 04 25 28 00 00 00 48 89 44 24 48 31 C0 48 8D 7C 24 14 48 C7 44 24 08 00 00 00 00 F3 AB 48 8D 7C 24 14 E8 }
    condition:
        any of them
}

rule M_Hunting_PacketEncryptionLayer_1 {
    meta:
        author = "Mandiant"
    strings:
        $pel_1 = "pel_client_init"
        $pel_2 = "pel_server_init"
        $pel_3 = "pel_setup_context"
        $pel_4 = "pel_send_msg"
        $pel_5 = "pel_recv_msg"
        $pel_6 = "pel_send_all"
        $pel_7 = "pel_recv_all"
        $pel_8 = "pel_errno"
        $pel_9 = "pel_context"
        $pel_10 = "pel_ctx"
        $pel_11 = "send_ctx"
        $pel_12 = "recv_ctx"
    condition:
        4 of ($pel_*)
}

rule M_Hunting_TINYSHELL_5 {
    meta:
        author = "Mandiant"
    strings:
        $tsh_1 = "tsh_get_file"
        $tsh_2 = "tsh_put_file"
        $tsh_3 = "tsh_runshell"
        $tshd_1 = "tshd_get_file"
        $tshd_2 = "tshd_put_file"
        $tshd_3 = "tshd_runshell"
    condition:
        all of ($tshd_*) or all of ($tsh_*)
}

rule detect_Auto_Color {
    meta:
        description = "Detects Auto-color malware family "
        author = "Mohamed Ezzat (@ZW01f)"
        hash1  = "815b74947d3a78a1b7d2aece43596ddc0ffc264e26092f1f9b6409c62e1437d6"
        hash2  = "270fc72074c697ba5921f7b61a6128b968ca6ccbf8906645e796cfc3072d4c43"

    strings:
        $elf = "\x7fELF" // ELF header
        $s1 = "/var/log/cross"  
        $s2 = "/tmp/cross"   
        $s3 = "/door-%d.log"  
        $s4 = "/etc/ld.so.preload.xxx" 
        $s5 = "%s/auto-color" ascii wide 
        $s6 = "%s memory dump %d bytes..." wide ascii

    condition:
        (filesize < 300KB) and ($elf at 0) and (5 of ($s*)) 
}

rule Linux_Hacktool_Outlaw_cf069e73 {
    meta:
        author = "Elastic Security"
        description = "OUTLAW SSH bruteforce component fom the Dota3 package"
        reference_sample = "c3efbd6b5e512e36123f7b24da9d83f11fffaf3023d5677d37731ebaa959dd27"
    strings:
        $ssh_key_1 = "MIIJrTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQI8vKBZRGKsHoCAggA"
        $ssh_key_2 = "MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAECBBBC3juWsJ7DsDd2wH2XI+vUBIIJ"
        $ssh_key_3 = "UCQ2viiVV8pk3QSUOiwionAoe4j4cBP3Ly4TQmpbLge9zRfYEUVe4LmlytlidI7H"
        $ssh_key_4 = "O+bWbjqkvRXT9g/SELQofRrjw/W2ZqXuWUjhuI9Ruq0qYKxCgG2DR3AcqlmOv54g"
        $path_1 = "/home/eax/up"
        $path_2 = "/var/tmp/dota"
        $path_3 = "/dev/shm/ip"
        $path_4 = "/dev/shm/p"
        $path_5 = "/var/tmp/.systemcache"
        $cmd_1 = "cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'"
        $cmd_2 = "cd ~; chattr -ia .ssh; lockr -ia .ssh"
        $cmd_3 = "sort -R b | awk '{ if ( NF == 2 ) print } '> p || cat b | awk '{ if ( NF == 2 ) print } '> p; sort -R a"
        $cmd_4 = "rm -rf /var/tmp/dota*"
        $cmd_5 = "rm -rf a b c d p ip ab.tar.gz"
    condition:
        (all of ($ssh_key*)) or (3 of ($path*) and 3 of ($cmd*))
}

rule SNOWLIGHT_DROPPER_SYSDIG {
        meta:
                author = "Alessandra Rizzo"
                description = "This rule detects strings seen in SNOWLIGHT malware acting as a dropper for fileless payloads."
                md5 = "96f307b0ba3bb11715fab5db8d61191f"
                platforms = "Linux"
                malware_family = "SNOWLIGHT"
        strings:
                $http_get_request = { 77 73 5f 00 6c 36 34 00 47 45 54 20 2f 3f 61 3d 25 73 26 68 3d 25 73 26 74 3d 25 73 26 70 3d 25 64 }
                $user_agent = { 55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 3b 20 72 76 3a 34 38 2e 30 29 20 47 65 63 6b 6f 2f 32 30 31 30 30 31 30 31 20 46 69 72 65 66 6f 78 2f 34 38 2e 30 }
  $fileless_payload_masked_name = { 5b 6b 77 6f 72 6b 65 72 2f 30 3a 32 }
        condition:
                uint32(0) == 0x464c457f and all of them
}

rule Linux_PumaBot {
  meta:
      description = "Rule to match on PumaBot samples"
      author = "tgould@cadosecurity.com"
  strings:
      $xapikey = "X-API-KEY" ascii
      $get_ips = "?count=5000" ascii
      $exec_start = "ExecStart=/lib/redis" ascii
      $svc_name1 = "redis.service" ascii
      $svc_name2 = "mysqI.service" ascii
      $uname = "uname -a" ascii
      $pumatronix = "Pumatronix" ascii
  condition:
      uint32(0) == 0x464c457f and
      all of (
          $xapikey,
          $uname,
          $get_ips,
          $exec_start
      ) and any of (
          $svc_name1,
          $svc_name2
      ) and $pumatronix
}

rule ELF_Chaos_RAT {
  meta:
     description = "Detects Linux ELF binaries <10MB with indicators of CHAOS-RAT-generated payloads"
     author = "Acronis TRU"
     date = "2025-04-16"
  strings:
     $chaos = "tiagorlampert/CHAOS" ascii
     $library1 = "BurntSushi/xgb" ascii
     $library2 = "gen2brain/shm" ascii
     $library3 = "kbinani/screenshot" ascii
  condition:
     uint32(0) == 0x464c457f and // ELF magic number in little-endian
     filesize < 10MB and $chaos and
     2 of ($library*)
}

rule MAL_LNX_PLAGUE_BACKDOOR_Jul25 {
   meta:
      description = "Detects Plague backdoor ELF binaries, related to PAM authentication alteration."
      reference = "Internal Research"
      author = "Pezier Pierre-Henri"
      date = "2025-07-25"
      score = 80
      hash = "14b0c90a2eff6b94b9c5160875fcf29aff15dcfdfd3402d953441d9b0dca8b39"
      hash = "7c3ada3f63a32f4727c62067d13e40bcb9aa9cbec8fb7e99a319931fc5a9332e"
   strings:
      $s1 = "decrypt_phrase"
      $s2 = "init_phrases"
   condition:
      uint32be(0) == 0x7f454c46
      and filesize < 1MB
      and all of them
}

rule MAL_ZYNOR {
   meta:
       md5 = "7422122eec7cfb3ec44737607d3ff5d2"
       description = "Detects ZynorRAT"
       author = "Sysdig TRT"
       date = "2025-08-04"
       tags = "zynor, ELF"
       reference = "Internal Research"
       version = "1.0"
   strings:
       $s1 = "main.handleShellCommand"
       $s2 = "main.handlePersistence"
       $s3 = "https://api.telegram.org/bot%s/sendMessage?chat_id=%d&text=%s" ascii
       $s4 = "https://api.telegram.org/bot%s/sendDocument" ascii
   condition:
       uint32(0) == 0x464c457f and
       1 of ($s1, $s2) and 1 of ($s3, $s4)
}

rule MAL_LinkPro_ELF_Rootkit_Golang_Oct25 {
  meta:
    description = "Detects LinkPro rootkit"
    author = "CSIRT Synacktiv, Théo Letailleur"
    date = "2025-10-13"
    reference = "https://www.synacktiv.com/en/publications/linkpro-ebpf-rootkit-analysis"
    hash = "1368f3a8a8254feea14af7dc928af6847cab8fcceec4f21e0166843a75e81964"
    hash = "d5b2202b7308b25bda8e106552dafb8b6e739ca62287ee33ec77abe4016e698b"
  strings:
    $linkp_mod = "link-pro/link-client" fullword ascii
    $linkp_embed_libld = "resources/libld.so" fullword ascii
    $linkp_embed_lkm = "resources/arp_diag.ko" fullword ascii
    $linkp_ebpf_hide = "hidePrograms" fullword ascii
    $linkp_ebpf_knock = "knock_prog" fullword ascii

    $go_pty = "creack/pty" fullword ascii
    $go_socks = "resocks" fullword ascii

  condition:
    uint32(0) == 0x464c457f and filesize > 5MB and elf.type == elf.ET_EXEC 
    and 2 of ($linkp*) 
    and 1 of ($go*)
}

rule MAL_LinkPro_Hide_ELF_BPF_Oct25 {
  meta:
    description = "Detects LinkPro Hide eBPF module"
    author = "CSIRT Synacktiv, Théo Letailleur"
    date = "2025-10-13"
    reference = "https://www.synacktiv.com/en/publications/linkpro-ebpf-rootkit-analysis"
    hash = "b8c8f9888a8764df73442ea78393fe12464e160d840c0e7e573f5d9ea226e164"
  strings:
    $hook_getdents = "/syscalls/sys_enter_getdents" fullword ascii
    $hook_getdentsret = "/syscalls/sys_exit_getdents" fullword ascii
    $hook_bpf = "/syscalls/sys_enter_bpf" fullword ascii
    $hook_bpfret = "sys_bpf" fullword ascii
    $str1 = "BPF cmd: %d, start_id: %u" fullword ascii
    $str2 = "HIDING NEXT_ID: %u" fullword ascii
    $str3 = ".tmp~data" fullword ascii

  condition:
    uint32(0) == 0x464c457f and uint16(0x12) == 0x00f7 // BPF Machine
    and elf.type == elf.ET_REL  
    and 2 of ($hook*)
    and 1 of ($str*)
}

rule MAL_LinkPro_Knock_ELF_BPF_Oct25 {
  meta:
    description = "Detects LinkPro Knock eBPF module"
    author = "CSIRT Synacktiv, Théo Letailleur"
    date = "2025-10-13"
    reference = "https://www.synacktiv.com/en/publications/linkpro-ebpf-rootkit-analysis"
    hash = "364c680f0cab651bb119aa1cd82fefda9384853b1e8f467bcad91c9bdef097d3"
  strings:
    $hook_xdp = "xdp_ingress" fullword ascii
    $hook_tc_egress = "tc_egress" fullword ascii
    $str1 = "[DBG-XDP]" fullword ascii
    $str2 = "[DBG-9999]" fullword ascii
    $str3 = "[TC-MISS]" fullword ascii
    $str4 = "[TC] REWRITE_BACK" fullword ascii
  condition:
    uint32(0) == 0x464c457f and uint16(0x12) == 0x00f7 // BPF Machine
    and elf.type == elf.ET_REL 
    and 1 of ($hook*)
    and 2 of ($str*)
}

rule MAL_LinkPro_LdPreload_ELF_SO_Oct25 {
  meta:
    description = "Detects LinkPro ld preload module"
    author = "CSIRT Synacktiv, Théo Letailleur"
    date = "2025-10-13"
    reference = "https://www.synacktiv.com/en/publications/linkpro-ebpf-rootkit-analysis"
    hash = "b11a1aa2809708101b0e2067bd40549fac4880522f7086eb15b71bfb322ff5e7"
  strings:
    $hook_getdents = "getdents" fullword ascii
    $hook_open = "open" fullword ascii
    $hook_readdir = "readdir" fullword ascii
    $hook_kill = "kill" fullword ascii
    $linkpro = ".tmp~data" fullword ascii
    $file_net = "/proc/net" fullword ascii
    $file_persist = ".system" fullword ascii
    $file_cron = "sshids" fullword ascii
  condition:
    uint32(0) == 0x464c457f and filesize < 500KB and elf.type == elf.ET_DYN
    and $linkpro
    and 2 of ($hook*)
    and 2 of ($file*)
}

rule MAL_LinkPro_arpdiag_ELF_KO_Oct25 {
  meta:
    description = "Detects LinkPro LKM module"
    author = "CSIRT Synacktiv, Théo Letailleur"
    date = "2025-10-13"
    reference = "https://www.synacktiv.com/en/publications/linkpro-ebpf-rootkit-analysis"
    hash = "9fc55dd37ec38990bb27ea2bc18dff0bb2d16ad7aa562ab35a6b63453c397075"
  strings:
    $hook_udp6 = "hook_udp6_seq_show" fullword ascii
    $hook_udp4 = "hook_udp4_seq_show" fullword ascii
    $hook_tcp6 = "hook_tcp6_seq_show" fullword ascii
    $hook_tcp4 = "hook_tcp4_seq_show" fullword ascii
    $ftrace = "ftrace_thunk" fullword ascii
    $hide_entry = "hide_port_init" fullword ascii
    $hide_exit = "hide_port_exit" fullword ascii
  condition:
    uint32(0) == 0x464c457f and filesize < 2MB and elf.type == elf.ET_REL
    and $ftrace
    and 2 of ($hook*) 
    and 1 of ($hide*)
}

rule MAL_vGet_ELF_Downloader_Rust_Oct25 {
  meta:
    description = "Detects vGet Downloader, observed to load vShell"
    author = "CSIRT Synacktiv, Théo Letailleur"
    date = "2025-10-13"
    reference = "https://www.synacktiv.com/en/publications/linkpro-ebpf-rootkit-analysis"
    hash = "0da5a7d302ca5bc15341f9350a130ce46e18b7f06ca0ecf4a1c37b4029667dbb"
    hash = "caa4e64ff25466e482192d4b437bd397159e4c7e22990751d2a4fc18a6d95ee2"
  strings:
    $hc_rust = "RUST_BACKTRACE"  fullword ascii
    $hc_symlink = "/tmp/.del"  fullword ascii
    $hc_proxy = "Proxy-Authorization:"  fullword ascii
    $lc_crypto_chacha = "expand 32-byte k"  fullword ascii
    $lc_pdfuser = "cosmanking"  fullword ascii
    $lc_local = "127.0.0.1" fullword ascii
  condition:
    uint32(0) == 0x464c457f and filesize > 500KB and filesize < 3MB 
    and elf.type == elf.ET_DYN 
    and all of ($hc*)
    and 1 of ($lc*)
}

rule Linux_Rootkit_BrokePKG_7b7d4581 {
    meta:
        author = "Elastic Security"
        id = "7b7d4581-ee4d-48c3-81e4-4264d68e8fe9"
        fingerprint = "5d771035e2bc4ffea1b9fd6f29c76ff5d9278db42167d3dab90eb0ac8d4bdd78"
        creation_date = "2024-11-13"
        last_modified = "2024-11-22"
        threat_name = "Linux.Rootkit.BrokePKG"
        reference_sample = "97c5e011c7315a05c470eef4032030e461ec2a596513703beedeec0b0c6ed2da"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $license1 = "author=R3tr074"
        $license2 = "name=brokepkg"
        $license3 = "description=Rootkit"
        $license4 = "license=GPL"
        $str1 = "brokepkg"
        $str2 = "brokepkg: module revealed"
        $str3 = "brokepkg: hidden module"
        $str4 = "brokepkg: given away root"
        $str5 = "brokepkg unloaded, my work has completed"
        $str6 = "br0k3_n0w_h1dd3n"
        $hook1 = "nf_inet_hooks"
        $hook2 = "ftrace_hook"
        $hook3 = "hook_getdents"
        $hook4 = "hook_kill"
        $hook5 = "hook_tcp4_seq_show"
        $hook6 = "hook_tcp6_seq_show"
        $hook7 = "orig_tcp6_seq_show"
        $hook8 = "orig_tcp4_seq_show"
        $hook9 = "orig_kill"
        $hook10 = "orig_getdents"
    condition:
        3 of ($license*) or 2 of ($str*) or 4 of ($hook*)
}

rule Linux_Rootkit_Generic_61229bdf {
    meta:
        author = "Elastic Security"
        id = "61229bdf-0b78-48b1-8a4d-09836dd2bcac"
        fingerprint = "8180ee7a04fd5ba23700e77ad3be7f30d592e77cffa8ebee8de7094627446335"
        creation_date = "2024-11-14"
        last_modified = "2024-11-22"
        threat_name = "Linux.Rootkit.Generic"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = "dropshell"
        $str2 = "fake_account_user_time"
        $str3 = "fake_bpf_trace_printk"
        $str4 = "fake_crash_kexec"
        $str5 = "fake_loadavg_proc_show"
        $str6 = "fake_sched_debug_show"
        $str7 = "fake_seq_show_ipv4_tcp"
        $str8 = "fake_seq_show_ipv4_udp"
        $str9 = "fake_seq_show_ipv6_tcp"
        $str10 = "fake_seq_show_ipv6_udp"
        $str11 = "fake_trace_printk"
        $str12 = "give_root"
        $str13 = "hack_getdents"
        $str14 = "hacked_getdents64"
        $str15 = "hacked_kill"
        $str16 = "hideModule"
        $str17 = "hide_module"
        $str18 = "hide_tcp4_port"
        $str19 = "hide_tcp6_port"
        $str20 = "hidden_tcp4_ports"
        $str21 = "hidden_tcp6_ports"
        $str22 = "hidden_udp4_ports"
        $str23 = "hidden_udp6_ports"
        $str24 = "hook_getdents"
        $str25 = "hook_kill"
        $str26 = "hook_local_in_func"
        $str27 = "hook_local_out_func"
        $str28 = "hook_tcp4_seq_show"
        $str29 = "hook_tcp6_seq_show"
        $str30 = "hooked_tcp6_seq_show"
        $str31 = "hooked_udp4_seq_show"
        $str32 = "hooked_udp6_seq_show"
        $str33 = "is_invisible"
        $str34 = "module_hide"
        $str35 = "module_show"
        $str36 = "nf_inet_hooks"
        $str37 = "old_access"
        $str38 = "old_fopen"
        $str39 = "old_lxstat"
        $str40 = "old_open"
        $str41 = "old_opendir"
        $str42 = "old_readdir"
        $str43 = "old_rmdir"
        $str44 = "old_unlink"
        $str45 = "old_xstat"
        $str46 = "orig_getdents"
        $str47 = "orig_getdents64"
        $str48 = "orig_kill"
        $str49 = "orig_tcp4_seq_show"
        $str50 = "orig_tcp6_seq_show"
        $str51 = "secret_connection"
        $str52 = "unhide_file"
        $str53 = "unhide_proc"
        $str54 = "unhide_tcp4_port"
        $str55 = "unhide_tcp6_port"
        $str56 = "unhide_udp4_port"
        $str57 = "unhide_udp6_port"
    condition:
        4 of ($str*)
}

rule Linux_Rootkit_Generic_482bca48 {
    meta:
        author = "Elastic Security"
        id = "482bca48-c337-45d9-9513-301909cbda73"
        fingerprint = "a2a005777e1bc236a30f3efff8d85af360665bd9418b77aa8d0aaf72a72df88a"
        creation_date = "2024-11-14"
        last_modified = "2024-12-09"
        threat_name = "Linux.Rootkit.Generic"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = "sys_call_table"
        $str2 = "kallsyms_lookup_name"
        $str3 = "retpoline=Y"
        $str4 = "kprobe"
        $rk1 = "rootkit"
        $rk2 = "hide_"
        $rk3 = "hacked_"
        $rk4 = "fake_"
        $rk5 = "hooked_"
        $hook1 = "_getdents"
        $hook2 = "_kill"
        $hook3 = "_seq_show_ipv4_tcp"
        $hook4 = "_seq_show_ipv4_udp"
        $hook5 = "_seq_show_ipv6_tcp"
        $hook6 = "_seq_show_ipv6_udp"
        $hook7 = "_tcp4_port"
        $hook8 = "_tcp4_seq_show"
        $hook9 = "_tcp6_port"
        $hook10 = "_tcp6_seq_show"
        $hook11 = "_udp4_port"
        $hook12 = "_udp4_seq_show"
        $hook13 = "_udp6_port"
        $hook14 = "_udp6_seq_show"
        $hook15 = "_unlink"
    condition:
        3 of ($str*) and ((all of ($rk*)) or (3 of ($rk*) and 5 of ($hook*)))
}

rule Linux_Rootkit_Generic_d0c5cfe0 {
    meta:
        author = "Elastic Security"
        id = "d0c5cfe0-850b-432c-924d-547252ca0dd0"
        fingerprint = "6c005d7126485220c8ea1a7fb2a3215ade16f1b9dda7b89daf7a8cc408288efa"
        creation_date = "2024-11-14"
        last_modified = "2024-12-09"
        threat_name = "Linux.Rootkit.Generic"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = "sys_call_table"
        $str2 = "kallsyms_lookup_name"
        $str3 = "retpoline=Y"
        $str4 = "kprobe"
        $init1 = "init_module"
        $init2 = "finit_module"
        $hook1 = "getdents"
        $hook2 = "seq_show_ipv4_tcp"
        $hook3 = "seq_show_ipv4_udp"
        $hook4 = "seq_show_ipv6_tcp"
        $hook5 = "seq_show_ipv6_udp"
        $hook6 = "sys_kill"
        $hook7 = "tcp4_port"
        $hook8 = "tcp4_seq_show"
        $hook9 = "tcp6_port"
        $hook10 = "tcp6_seq_show"
        $hook11 = "udp4_port"
        $hook12 = "udp4_seq_show"
        $hook13 = "udp6_port"
        $hook14 = "udp6_seq_show"
        $rk1 = "rootkit"
        $rk2 = "dropper"
        $rk3 = "hide"
        $rk4 = "hook"
        $rk5 = "hacked"
    condition:
        2 of ($str*) and 1 of ($init*) and 3 of ($hook*) and 3 of ($rk*)
}

rule Linux_Rootkit_Generic_f07bcabe {
    meta:
        author = "Elastic Security"
        id = "f07bcabe-f91e-4872-8677-dee6307e79d0"
        fingerprint = "7335426e705383ff6f62299943a139390b83ce2af4cbfc145cfe78c0f0015a26"
        creation_date = "2024-12-02"
        last_modified = "2024-12-09"
        threat_name = "Linux.Rootkit.Generic"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = "fh_install_hook"
        $str2 = "fh_remove_hook"
        $str3 = "fh_resolve_hook_address"
    condition:
        2 of them
}

rule Linux_Rootkit_Generic_5d17781b {
    meta:
        author = "Elastic Security"
        id = "5d17781b-5d2a-4405-8806-274e6cabfe2c"
        fingerprint = "220eff54c80a69c3df0d8f71aeacdd114cc2ea0675595c2bfde2ac47578c3a02"
        creation_date = "2024-12-02"
        last_modified = "2025-06-10"
        threat_name = "Linux.Rootkit.Generic"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str = "kallsyms_lookup_name_t"
        $lic1 = "license=Dual BSD/GPL"
        $lic2 = "license=GPL"
    condition:
        $str and 1 of ($lic*)
}

rule PCPcat_react_py {
    meta:
        description = "PCPcat React.py scanner"
        author = "Threat Intel"
        date = "2025-12-14"
    strings:
        $s1 = "CVE-2025-29927" nocase
        $s2 = "PCPcat" nocase
        $s3 = "67.217.57.240:5656" nocase
        $s4 = "deploy_pcpcat"
        $s5 = "extract .env"
    condition:
        (2 of them)
}

rule PCPcat_proxy_sh {
    meta:
        description = "PCPcat proxy.sh installer"
    strings:
        $s1 = "pcpcat-gost.service"
        $s2 = "pcpcat-frp.service"
        $s3 = "67.217.57.240:888"
        $s4 = "FRP_VERSION"
    condition:
        3 of them
}

rule PCPcat_API_Signature {
    meta:
        description = "PCPcat C2 API communication pattern"
    strings:
        $s1 = "/domains?client=" nocase
        $s2 = "/result" nocase
        $s3 = "\"env\":" nocase
        $s4 = "67.217.57.240:5656"
    condition:
        all of them
}

rule CISA_251165_02 : BRICKSTORM backdoor installs_other_components communicates_with_c2 exfiltrates_data {
    meta:
        author = "CISA Code & Media Analysis"
        incident = "251165"
        date = "2025-09-29"
        last_modified = "202051001_1008"
        actor = "n/a"
        family = "BRICKSTORM"
        capabilities = "installs-other-components communicates-with-c2 exfiltrates-data"
        malware_type = "backdoor"
        tool_type = "unknown"
        description = "Detects Go-Based BRICKSTORM backdoor samples"
        sha256_1 = "aaf5569c8e349c15028bc3fac09eb982efb06eabac955b705a6d447263658e38"
    strings:
        $s0 = { 6D 61 69 6E 2E 73 74 61 72 74 4E 65 77 }
        $s1 = { 6D 61 69 6E 2E 73 65 6C 66 57 61 74 63 68 65 72 }
        $s2 = { 6D 61 69 6E 2E 73 65 74 53 65 72 76 69 63 65 43 66 67 }
        $s3 = { 73 6F 63 6B 73 2E 48 61 6E 64 6C 65 53 6F 63 6B 73 52 65 71 75 65 73 74 }
        $s4 = { 77 65 62 2E 57 65 62 53 65 72 76 69 63 65 }
        $s5 = { 63 6F 6D 6D 61 6E 64 2E 48 61 6E 64 6C 65 54 54 59 52 65 71 75 65 73 74 }
        $s6 = { 77 65 62 73 6F 63 6B 65 74 2E 28 2A 57 53 43 6F 6E 6E 65 63 74 6F 72 29 2E 43 6F 6E 6E 65 63 74 }
        $s7 = { 66 73 2E 28 2A 57 65 62 53 65 72 76 65 72 29 2E 52 75 6E 53 65 72 76 65 72 }
        $s8 = { 68 74 74 70 73 3A 2F 2F 31 2E 30 2E 30 2E 31 2F 64 6E 73 2D 71 75 65 72 79 }
        $s9 = { 68 74 74 70 73 3A 2F 2F 31 2E 31 2E 31 2E 31 2F 64 6E 73 2D 71 75 65 72 79 }
        $s10 = { 68 74 74 70 73 3A 2F 2F 38 2E 38 2E 34 2E 34 2F 64 6E 73 2D 71 75 65 72 79 }
        $s11 = { 68 74 74 70 73 3A 2F 2F 38 2E 38 2E 38 2E 38 2F 64 6E 73 2D 71 75 65 72 79 }
        $s12 = { 68 74 74 70 73 3A 2F 2F 39 2E 39 2E 39 2E 39 2F 64 6E 73 2D 71 75 65 72 79 }
    condition:
        8 of them
}

rule CISA_251155_02 : BRICKSTORM backdoor installs_other_components communicates_with_c2 exfiltrates_data {
    meta:
        author = "CISA Code & Media Analysis"
        incident = "251155"
        date = "2025-09-15"
        last_modified = "20250916_1511"
        actor = "n/a"
        family = "BRICKSTORM"
        capabilities = "installs-other-components communicates-with-c2 exfiltrates-data"
        malware_type = "backdoor"
        tool_type = "unknown"
        description = "Detects Go-Based BRICKSTORM backdoor samples"
        sha256_1 = "320a0b5d4900697e125cebb5ff03dee7368f8f087db1c1570b0b62f5a986d759"
        sha256_1 = "dfac2542a0ee65c474b91d3b352540a24f4e223f1b808b741cfe680263f0ee44"
        sha256_1 = "b91881cb1aa861138f2063ec130b2b01a8aaf0e3f04921e5cbfc61b09024bf12"
        sha256_1 = "bfb3ffd46b21b2281374cd60bc756fe2dcc32486dcc156c9bd98f24101145454"
    strings:
        $s0 = { 04 30 0F B6 54 04 2C 31 D1 88 4C 04 34 48 FF C0 }
        $s1 = { 48 83 F8 04 7C E7 48 C7 04 24 }
        $s2 = { 48 8D 44 24 34 48 89 44 24 08 48 C7 44 24 10 04 }
        $s3 = { 48 89 44 24 48 48 89 4C 24 50 48 8B 6C 24 38 48 }
        $s4 = { 48 83 EC 40 48 89 6C 24 38 48 8D 6C 24 38 C7 44 24 }
        $s5 = { 83 EC 38 48 89 6C 24 30 48 8D 6C 24 30 C6 44 24 }
        $s6 = { 4C 24 20 48 89 44 24 40 48 89 4C 24 48 48 8B 6C }
        $s7 = { 64 48 8B 0C 25 F8 FF FF FF 48 3B 61 10 0F 86 81 }
        $s8 = { 64 48 8B 0C 25 F8 FF FF FF 48 3B 61 10 0F 86 91 }
    condition:
        all of them
}

rule CISA_251155_01 : BRICKSTORM backdoor installs_other_components communicates_with_c2 exfiltrates_data {
    meta:
        author = "CISA Code & Media Analysis"
        incident = "251155"
        date = "2025-09-15"
        last_modified = "20250916_1511"
        actor = "n/a"
        family = "BRICKSTORM"
        capabilities = "installs-other-components communicates-with-c2 exfiltrates-data"
        malware_type = "backdoor"
        tool_type = "unknown"
        description = "Detects Go-Based BRICKSTORM backdoor samples"
        sha256_1 = "2bf9bfa1f9bcbcad0eada7e3be8d380d809248f08609f6e9d971b37ce09f7e93"
        sha256_2 = "6d42e9a0757670b9837034b5202d1673093577757b44bb0f0253f366413393e9"
        sha256_3 = "b30041b986ee3231fd53522c9d0c57e4567d6c60959fa06c125dde2af558fc9f"
    strings:
        $s0 = { 88 14 08 48 FF C1 }
        $s1 = { 2F 63 6F 72 65 2F 74 61 73 6B 2E 44 6F 54 61 73 6B 2E 66 75 6E 63 31 }
        $s2 = { 2F 63 6F 72 65 2F 74 61 73 6B 2E 44 6F 54 61 73 6B 2E 66 75 6E 63 31 2E 32 }
        $s3 = { 2F 63 6F 72 65 2F 65 78 74 65 6E 64 73 2F 77 65 62 2E 57 65 62 53 65 72 76 69 63 65 }
        $s4 = { 2F 63 6F 72 65 2F 65 78 74 65 6E 64 73 2F 77 65 62 2E 57 65 62 53 65 72 76 69 63 65 2E 66 75 6E 63 31 }
        $s5 = { 63 6F 72 65 2F 65 78 74 65 6E 64 73 2F 73 6F 63 6B 73 2E 53 6F 63 6B 73 }
        $s6 = { 63 6F 72 65 2F 65 78 74 65 6E 64 73 2F 73 6F 63 6B 73 2E 53 6F 63 6B 73 2E 66 75 6E 63 31 }
        $s7 = { 63 6F 72 65 2F 65 78 74 65 6E 64 73 2F 63 6F 6D 6D 61 6E 64 2E 43 6F 6D 6D 61 6E 64 }
        $s8 = { 6C 69 62 73 2F 64 6F 68 2E 51 75 65 72 79 }
        $s9 = { 2F 76 65 6E 64 6F 72 2F 68 61 73 68 69 63 6F 72 70 2F 79 61 6D 75 78 2E 53 65 72 76 65 72 }
    condition:
        3 of them
}

rule CISA_251217_03 : BRICKSTORM backdoor installs_other_components communicates_with_c2 exfiltrates_data {
    meta:
        author = "CISA Code & Media Analysis"
        incident = "251217"
        date = "2025-12-10"
        last_modified = "20251216_729"
        actor = "n/a"
        family = "BRICKSTORM"
        capabilities = "installs-other-components communicates-with-c2 exfiltrates-data"
        malware_type = "backdoor"
        tool_type = "unknown"
        description = "Detects Rust BRICKSTORM backdoor samples"
        sha256_1 = "6a67a9769a55ec889a5dd4199b2fc08965d39d737838836853bc13c81c56a800"
        sha256_2 = "ed907d39efd5750236b075ca9fbb1f090d7bf578578c38faab24210d298a60ae" 
        sha256_3 = "0e92009fc6519c837982b3fbfd42946e827de47b73a264d693739168533d07f4"
        sha256_4 = "fb22eea57e00b83edad50ee6e02320377efc10586584c476d5018dbba3643c32"
        sha256_5 = "28a16e782f04d9394b5dfa3363d41d9f5eecc206166aeffd73363d83734a026d"
        strings:
        $s0 = { 20 55 70 67 72 61 64 65 3A 20 77 65 62 73 6F 63 6B 65 74 43 6F 6E 6E 65 63 74 69 6F 6E 3A }
        $s1 = { 20 55 70 67 72 61 64 65 53 65 63 2D 57 65 62 73 6F 63 6B 65 74 2D 4B 65 79 3A }
        $s2 = { 20 53 65 63 2D 57 65 62 53 6F 63 6B 65 74 2D 56 65 72 73 69 6F 6E 3A }
        $s3 = { 57 65 62 53 6F 63 6B 65 74 53 65 63 2D 57 65 62 53 6F 63 6B 65 74 2D 41 63 63 65 70 74 3A }
        $s4 = { 53 77 69 74 63 68 69 6E 67 20 50 72 6F 74 6F 63 6F 6C 73 }
        $s5 = { 32 35 38 45 41 46 41 35 2D 45 39 31 34 2D 34 37 44 41 2D 39 35 43 41 2D 43 35 41 42 30 44 43 38 35 42 31 31 }
        $s6 = { 2F 64 65 76 2F 70 74 6D 78 64 6F 20 66 6F 72 6B 6F 70 65 6E 20 }
        $s7 = { 53 6F 63 6B 73 35 20 63 6D 64 20 6E 6F 74 20 73 75 70 70 6F 72 74 }
        $s8 = { 62 39 32 37 35 38 61 39 61 65 66 31 63 65 66 37 62 37 39 65 32 62 37 32 63 33 64 38 62 61 31 31 33 65 35 34 37 66 38 39 }
        $s9 = { 58 34 34 38 52 69 6E 67 47 45 54 20 0D 0A 0D 0A 70 69 70 65 50 69 6E 67 50 6F 6E 67 44 61 74 61 }
    condition:
        9 of them
}

rule CISA_251155_03 : BRICKSTORM backdoor installs_other_components communicates_with_c2 exfiltrates_data {
    meta:
        author = "CISA Code & Media Analysis"
        incident = "251155"
        date = "2025-09-15"
        last_modified = "20250916_1511"
        actor = "n/a"
        family = "BRICKSTORM"
        capabilities = "installs-other-components communicates-with-c2 exfiltrates-data"
        malware_type = "backdoor"
        tool_type = "unknown"
        description = "Detects Go-Based BRICKSTORM backdoor samples"
        sha256_1 = "0cba5c6d16c7b94a450c36bfbaeab79107ac10aa9548b02c42b4b6ba8cef6a51"
    strings:
        $s0 = { CE 73 63 44 0F B6 04 30 44 31 C7 48 83 FE 19 72 DA EB 53 48 C7 04 24 }
        $s1 = { 64 48 8B 0C 25 F8 FF FF FF 48 8D 44 24 E8 48 3B }
        $s2 = { 8D 44 24 5F 48 89 04 24 48 8D 05 F9 4C 12 00 48 }
        $s3 = { 8B 4C 24 20 48 89 4C 24 30 48 8D 54 24 58 48 89 }
        $s4 = { 8B 44 24 20 48 89 44 24 30 48 8B 4C 24 18 48 89 }
        $s5 = { E8 8E 6A D5 FF 48 8B 44 24 18 48 89 84 24 98 }
        $s6 = { E8 A4 69 D5 FF 48 8B 44 24 20 48 8B 4C 24 28 48 89 84 24 B0 }
        $s7 = { 48 8D 44 24 3F 48 89 44 24 08 48 C7 44 24 10 19 }
    condition:
        all of them
}

rule CISA_251186_02 : BRICKSTORM backdoor installs_other_components communicates_with_c2 exfiltrates_data {
    meta:
        author = "CISA Code & Media Analysis"
        incident = "251186"
        date = "2025-11-17"
        last_modified = "n/a"
        actor = "n/a"
        family = "BRICKSTORM"
        capabilities = "installs-other-components communicates-with-c2 exfiltrates-data"
        malware_type = "backdoor"
        tool_type = "unknown"
        description = "Detects Go-Based BRICKSTORM backdoor samples"
        sha256_1 = "57bd98dbb5a00e54f07ffacda1fea91451a0c0b532cd7d570e98ce2ff741c21d"
    strings:
        $s0 = { 31 F7 40 88 7C 04 4C 48 FF C0 }
        $s1 = { 44 01 C7 40 88 7C 14 30 48 FF C2 0F 1F 00 }
        $s2 = { 41 89 F0 31 FE 01 D6 66 90 49 83 F8 11 }
        $s3 = { 48 8B 44 24 08 48 8B 5C 24 10 48 8B 4C 24 18 }
        $s4 = { 48 89 C1 48 89 DF 48 8D 05 0F 6F 15 00}
        $s5 = { 48 8D 3D 9A 6D 15 00 4D 89 C1 49 89 F0 }
        $s6 = { 81 39 49 43 4D 50 74 0C }
        $s7 = { E8 FB E6 FF FF E8 76 D0 FF FF E8 91 C0 FF FF 48 8B 05 EA BF 53 }
    condition:
        all of them
}

rule Multi_Hacktool_Gsocket_761d3a0f {
    meta:
        author = "Elastic Security"
        id = "761d3a0f-e2e8-4a8a-99f6-7356555a517d"
        fingerprint = "e4426c5faa5775bcfdfbe01c3d6a2b4042aa9bf942883b104c241d0734b272c9"
        creation_date = "2024-09-20"
        last_modified = "2024-11-04"
        threat_name = "Multi.Hacktool.Gsocket"
        reference_sample = "193efd61ae10f286d06390968537fa85e4df40995fd424d1afe426c089d172ab"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $str1 = "gsocket: gs_funcs not found"
        $str2 = "/share/gsocket/gs_funcs"
        $str3 = "$GSOCKET_ARGS"
        $str4 = "GSOCKET_SECRET"
        $str5 = "GS_HIJACK_PORTS"
        $str6 = "sftp -D gs-netcat"
        $str7 = "GS_NETCAT_BIN"
        $str8 = "GSOCKET_NO_GREETINGS"
        $str9 = "GS-NETCAT(1)"
        $str10 = "GSOCKET_SOCKS_IP"
        $str11 = "GSOCKET_SOCKS_PORT"
        $str12 = "gsocket(1)"
        $str13 = "gs-sftp(1)"
        $str14 = "gs-mount(1)"
    condition:
        3 of them
}

rule Babuk_Payload_Ransomware_ESXi {
    meta:
        id = "BsSWXZd0LuupvmhUQc8Tla"
        fingerprint = "91664e63f9a66b83da3ac2cf4d24a5c98f837c579415a0baa68c556ca88b4d67"
        version = "1.0"
        date = "2026-03-15"
        modified = "2026-03-15"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "HTTPS://GITHUB.COM/KIRKDERP/YARA"
        author = "kirkderp"
        description = "Babuk Payload ransomware Linux/ESXi variant - Curve25519 + ChaCha20 encryption, FBI RC4 footer key, ESXi VM inventory targeting"
        category = "MALWARE"
        malware = "BABUK"
        malware_type = "RANSOMWARE"
        mitre_att = "T1486"
        reference = "https://github.com/kirkderp/yara"
        triage_score = 10
        triage_description = "Babuk Payload ransomware ESXi locker detected. Curve25519 ECDH + ChaCha20 file encryption targeting VMware ESXi."
        yarahub_uuid = "240635a3-ad8a-45ec-9176-815e4fa86fb2"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "e0fd8ff6d39e4c11bdaf860c35fd8dc0"

    strings:
        // "FBI" fused with thread pool format string -- builder artifact
        // FBI is the 3-byte RC4 key for footer encryption, concatenated with thpool format
        $fbi_thpool = "FBIthread-pool-%d" ascii

        // ChaCha20 constant
        $chacha = "expand 32-byte k" ascii

        // Branding
        $payload = "payload" ascii

        // Ransom note extension (RECOVERY-xx0001.txt)
        $note_ext = ".xx0001" ascii

        // Anti-debug: reads TracerPid from /proc/self/status
        $antidebug = "TracerPid:" ascii

        // Self-inspection
        $proc_self = "/proc/self/exe" ascii

        // Thread pool error messages (C-Thread-Pool library)
        $thpool_err1 = "thpool_init(): Could not allocate memory for thread pool" ascii
        $thpool_err2 = "thpool_add_work(): Could not allocate memory for new job" ascii
        $thpool_err3 = "thread_do(): cannot handle SIGUSR1" ascii

    condition:
        uint32(0) == 0x464C457F
        and filesize > 20KB and filesize < 500KB
        and (
            // High confidence: FBI+thpool artifact + ChaCha20 (unique to Payload builder)
            ($fbi_thpool and $chacha)
            or
            // High confidence: FBI+thpool + payload branding + note extension
            ($fbi_thpool and $payload and $note_ext)
            or
            // Medium confidence: ChaCha20 + payload branding + anti-debug + thpool errors
            ($chacha and $payload and $antidebug and 1 of ($thpool_err1, $thpool_err2, $thpool_err3))
            or
            // Medium confidence: note ext + ChaCha20 + proc inspection + thpool
            ($note_ext and $chacha and $proc_self and 1 of ($thpool_err1, $thpool_err2))
        )
}

rule ELF_RANSOMWARE_BLACKCAT : LinuxMalware {
    meta:
        description = "Detect Linux version of BlackCat Ransomware"
        author = "Jesper Mikkelsen"
        reference = "https://www.virustotal.com/gui/file/056d28621dca8990caf159f8e14069a2343b48146473d2ac586ca9a51dfbbba7"
        date = "2022-05-10"
        yarahub_reference_md5 = "c7e39ead7df59e09be30f8c3ffbf4d28"
        yarahub_uuid = "4354fe5a-ee0c-47e3-a595-2824dd82928d"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        techniques = "File and Directory Permissions Modification: Linux and Mac File and Directory Permissions Modification"
        tactic = "Defense Evasion"
        mitre_att = "T1222.002"
        sharing = "TLP:WHITE"
        dname = "Ransom.Linux.BLACKCAT.YXCDFZ"
        score = 75
    strings:
        $pattern0 = "sbin*/cdrom*/dev*/etc*/lib**lost+found*/proc*/run*/snap*/tmp*/sys*/usr*/bi"
        $pattern1 = "n `vim-cmd vmsvc/getallvms| awk '{print$1}'`;do vim-cmd vmsvc/sn"
        $pattern2 = { BB 6C EA 3F AA 84 31 C4 13 19 F2
               4C 47 F1 29 B7 FE 88 43 CA EF 60
               98 31 56 7A 97 30 CD 92 4C CB 74
               EB 26 B6 65 03 FD 4D DC D1 A1 A7
               CC 39 7A 5C 75 40 10 21 64 A8 CB
               DA DD B2 C4 DB 46 5A 1F 20 }
        $pattern3 = { 78 15 58 9C 99 1A C5 47 BC 7B B9
               31 5D 74 24 C7 E9 E0 72 B1 08 EF
               EF 6A 2D 8E 93 1C CC 81 0E DC 66
               4C 6B AA 87 43 F6 71 A2 22 8A 07
               43 2D 17 9D CB 0B 27 EB 2A 04 BA
               30 0F 65 C6 46 EE 6A 5B 86 }
        $pattern4 = { 72 78 B3 93 0F 69 5B 48 F4 D0 89
               14 1E C0 61 CF E5 79 18 A5 98 68
               F0 7E 63 D1 EA 71 62 4A 02 AA 99
               F3 7B C0 E4 E2 93 1B 1F 5B 0E D8
               97 0F E6 03 6C B6 9F 69 11 A7 77
               B2 EA 1E 6D BD EB 85 85 66 }
        $pattern5 = { 39 67 68 97 DB 59 03 55 34 5A B8
               62 DF 64 D3 A0 30 D1 0A 58 A9 EF
               61 9A 46 EC DA AD AD D2 B1 6F 42
               AB AA B3 A0 95 C1 71 4F 96 7A 46
               A4 A8 11 84 4B 25 4A 8F BA 1B 21
               4D 55 18 9A 7A BE 26 F1 B8 51 }
        $pattern6 = { 4B 35 35 C4 3D D4 3A 59 A7 5C 1C
               69 D1 BD 13 F4 0A 98 72 88 7C 79
               7D 15 BC D3 B0 70 CA 32 BF ED 11
               17 DE 91 67 F6 D1 0C 91 42 45 5A
               E7 A3 4A C7 3C 86 2B BB 4A 67 24
               26 8A CD E9 43 FC 2C E6 DE 27 09
               87 A2 51 E8 88 3F }
        $pattern7 = { 6B DA AE D5 B0 21 17 CF BF 20 8C
               27 64 DB 35 5E 0E A6 24 B6 D5 5D
               9D 2B 16 D5 C9 C3 CD 2E 70 BA A7
               53 61 52 7C A8 D8 48 73 A9 43 A0
               A8 52 FA D9 C2 2F EB 31 19 D4 52
               BB F0 87 4E 53 2B 7C F7 2A 41 01
               E6 C2 9A FA 5F D8 95 FB C4 }
    condition:
        all of them
}

rule ELF_RAT_Bifrost_March2024 {
    meta:
        Description = "Detects x86 based Version of Bifrost RAT Targeting Linux"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Reference = "https://unit42.paloaltonetworks.com/new-linux-variant-bifrost-malware/"
        Hash = "8e85cb6f2215999dc6823ea3982ff4376c2cbea53286e95ed00250a4a2fe4729"
        date = "2024-03-04"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "e527b3f10217c1d663e567e041947033"
        yarahub_uuid = "78f51ca6-2127-4e25-a710-2479388c1504"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "elf.bifrost"

   strings:
        $msg1 = "begin st=socket(..)"
        $msg2 = "ip=%s dns_server=%s"
        $msg3 = "sleep sleeptime_1 %ds"
        $msg4 = "recvData timeout :%d"
        $msg5 = "send data %d : %s"
        $msg6 = "restlen=%d"

        $cmd1 = "getpwuid_r"
        $cmd2 = "passwd"
        $cmd3 = "shadow"
        $cmd4 = "search cache=%s"
        $cmd5 = "lookup in file=%s"

        $dir1 = "/proc/self/maps"
        $dir2 = "/usr/share/zoneinfo"
        $dir3 = "/etc/nsswitch.conf"
        $dir4 = "/var/run/.nscd_socket"
        $dir5 = "/etc/suid-debug"
        $dir6 = "/usr/lib/gconv"
        $dir7 = "/usr/lib/locale/locale-archive"
        $dir8 = "/etc/resolv.conf"
        $dir9 = "/etc/ld.so.cache"
        $dir10 = "/proc/self/exe"

        //$_c2 = "168.95.1.1"
        $wide = "jjjjjj" wide

   condition:
         uint32be(0) == 0x7F454C46 //ELF
         and 4 of ($msg*)
         and 3 of ($cmd*)
         and 6 of ($dir*)
         and $wide
}

rule ELF_RAT_Dinodas_April2024 {
    meta:
        Description = "Detects Linux Variant of Dinodas RAT"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Reference = "https://securelist.com/dinodasrat-linux-implant/112284/"
        File_Hash_1 = "15412d1a6b7f79fad45bcd32cf82f9d651d9ccca082f98a0cca3ad5335284e45"
        File_Hash_2 = "bf830191215e0c8db207ea320d8e795990cf6b3e6698932e6e0c9c0588fc9eff"
        date = "2024-04-01"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "8138f1af1dc51cde924aa2360f12d650"
        yarahub_uuid = "3262efcd-9716-4030-8afa-a4e4c8d71c54"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.dinodas_rat"

    strings:
        $key1 = {A1 A1 18 AA 10 F0 FA 16 06 71 B3 08 AA AF 31 A1} // For C2 encryption
        $key2 = {A0 21 A1 FA 18 E0 C1 30 1F 9F C0 A1 A0 A6 6F B1} // For name encryption

        $c2 = "update.centos-yum.com:443" fullword     // Hardcoded C2 domain

        $etc1 = "/etc/rc.d/rc.local" fullword
        $etc2 = "/etc/init.d/%s" fullword
        $etc3 = "cat /proc/version" fullword
        $etc4 = "cat /etc/lsb-release" fullword
        $etc5 = "/etc/rc.local" fullword

        $chck1 = "chkconfig --add %s" fullword
        $chck2 = "chkconfig zentao %s" fullword
        $chck3 = "whereis chkconfig" fullword
        $chck4 = "chkconfig --list" fullword
        $chck5 = "chkconfig --del %s" fullword

        $cmd1 = "kill %u" fullword
        $cmd2 = "kill %s" fullword
        $cmd3 = "rm -rf" fullword
        $cmd4 = "getconf LONG_BIT" fullword
        $cmd5 = "ls -l /proc/%s/exe" fullword
        $cmd6 = "service %s start" fullword
        $cmd7 = "service %s stop" fullword
        $cmd8 = "nslookup %s %s" fullword

        $info1 = "ExecStart=/etc/rc.local start" fullword
        $info2 = "After=network.target" fullword
        $info3 = "Default-Start: 2 3 4 5" fullword
        $info4 = "Default-Stop: 0 1 6" fullword
        $info5 = "multi-user.target" fullword

    condition:
        uint32be(0) == 0x7F454C46  //ELF Header
        and any of ($key*)

        and ($c2 or
        (any of ($chck*)
        and 2 of ($etc*)
        and 3 of ($cmd*)
        and 2 of ($info*)))

        and filesize < 1MB
}

rule elf_rekoobe_b3_06c9 {
    meta:
        author                    = "Johannes Bader"
        date                      = "2022-09-02"
        description               = "detects the Rekoobe Linux backdoor"
        hash1_md5                 = "55ab7e652976d25997875f678c935de7"
        hash1_sha1                = "dc6beb5019ee21ab207c146ece5080d00f20a103"
        hash1_sha256              = "a89ebd7157336141eb14ed9084491cc5bdfce103b4db065e433dff47a1803731"
        tlp                       = "TLP:WHITE"
        version                   = "v1.0"
        yarahub_author_email      = "yara@bin.re"
        yarahub_author_twitter    = "@viql"
        yarahub_license           = "CC BY-SA 4.0"
        yarahub_reference_md5     = "55ab7e652976d25997875f678c935de7"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        yarahub_uuid              = "06c95657-8897-443c-bc8e-f0f5cf6cf055"
    strings:
        $sha_1  = {01 23 45 67 [0-10] 89 AB CD EF [0-10] FE DC BA 98 [0-10] 76 54 32 10 [0-10] F0 E1 D2 C3}

        $hmac_1 = {36 36 36 36 36 36 36 36}
        $hmac_2 = {5C 5C 5C 5C 5C 5C 5C 5C}

        $str_term_1  = {C6 00 54}
        $str_term_2  = {C6 40 03 4D}
        $str_term_3  = {C6 40 01 45}
        $str_term_4  = {C6 40 04 3D}
        $str_term_5  = {C6 40 02 52}
        $str_term_6  = {C6 40 02 52}

        $str_histfile_1 = {C6 00 48}
        $str_histfile_2 = {C6 40 05 49}
        $str_histfile_3 = {C6 40 01 49}
        $str_histfile_4 = {C6 40 06 4C}
        $str_histfile_5 = {C6 40 02 53}
        $str_histfile_6 = {C6 40 07 45}
        $str_histfile_7 = {C6 40 03 54}
        $str_histfile_8 = {C6 40 08 3D}
        $str_histfile_9 = {C6 40 04 46}
    condition:
        uint32(0) == 0x464C457F and
        (
            all of them
        )
}

rule Linux_Downloader {
    meta:
        author = "@P4nd3m1cb0y"
        description = "Detects a Linux downloader targeting x64, x86, and arm64 architectures."
        date = "2024-08-18"
        reference = "https://x.com/Huntio/status/1823280152845107543"
        hash = "3fd87c6e3d681d7f7909902899e1bce6c5095cf5" // x86 version
        hash = "7b276653c3e09010c4ec0afe3f44859ec1f5d65d" // x64 version
        hash = "12cbba0f00dbf73ce66ed33e115dee2e9a25add2" // arm64 version

        yarahub_reference_md5 = "85d2c22b576a80d2d1da591b0d3a5d26"
        yarahub_uuid = "cc1c56e6-a083-41d2-bbee-9f62e8af37c3"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
    strings:
        $s1 = "/usr/sbin/systemd" ascii
        $s2 = "./systemd" ascii
        $s3 = "[kworker/0:2]" ascii
        $arch1 = "l64" ascii
        $arch2 = "l32" ascii
        $arch3 = "a64" ascii

        $sock_x64 = { BA 00 00 00 00 BE 01 00 00 00 BF 02 00 00 00 E8 ?? ?? ?? ?? }
        /*
            BA 00 00 00 00  mov     edx, IPPROTO_IP
            BE 01 00 00 00  mov     esi, SOCK_STREAM
            BF 02 00 00 00  mov     edi, AF_INET
            E8 ?? ?? ?? ??  call    socket
        */
        $sock_x86 = { 6A 00 6A 01 6A 02 E8 ?? ?? ?? }
        /*
            6A 00           push    0
            6A 01           push    1
            6A 02           push    2
            E8 ?? ?? ??     call    socket
        */
        $sock_arm64 = { 02 00 80 52 21 00 80 52 40 00 80 52 ?? 69 00 94 }
        /*
            02 00 80 52     mov        w2,#0x0
            21 00 80 52     mov        w1,#0x1
            40 00 80 52     mov        w0,#0x2
            ?? 69 00 94     bl         socket
        */
    condition:
        uint32(0) == 0x464C457F and
        filesize < 1MB and
        (3 of ($s*) and 1 of ($sock*) and 1 of ($arch*))
}

rule Linux_SSHBruteforce_PRG_OLDTEAM {
    meta:
        description = "Linux SSH brute-force toolkit (PRG / OLDTEAM), often masquerading as image"
        author = "noopoo/0XFF1"
        date = "2026-02-06"
        malware_family = "PRG-OLDTEAM"
        yarahub_license = "CC0 1.0"
        yarahub_uuid = "d3c74bf4-4cf9-4ff2-b6c6-c0767888e68c"
        reference = "MalwareBazaar upload"
        yarahub_reference_md5 = "d1ca004fbda5fedcd6583b09b679c581"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
    strings:
        /* Identity / Ego */
        $id1 = "PRG-oldTeam" ascii nocase
        $id2 = "OLDTEAM" ascii
        $id3 = "LET'S MAKE SOME ADMINS TO CRY" ascii nocase
        $id4 = "CREATED BY PRG" ascii

        /* Config / workflow */
        $cfg1 = "ips.lst" ascii
        $cfg2 = "pass.lst" ascii
        $cfg3 = "uidThreads" ascii
        $cfg4 = "usrThreads" ascii
        $cfg5 = "Banner grabber starting" ascii

        /* SSH / libssh2 internals */
        $ssh1 = "Invalid MAC received" ascii
        $ssh2 = "Channel open failure" ascii
        $ssh3 = "libssh2" ascii
        $ssh4 = "Unable to send channel data" ascii

        /* Packaging / structure */
        $pkg1 = ".stx/" ascii
        $pkg2 = "ustar" ascii
        $pkg3 = "gzip compressed data" ascii
    condition:
        /* Identity is mandatory */
        1 of ($id*) and

        /* Must show brute-force behavior */
        2 of ($cfg*) and
        2 of ($ssh*) and

        /* Plus archive / delivery context */
        1 of ($pkg*)
}

rule Linux_XMR_Miner_xmra64 {
    meta:
        author = "0xFF1"
        description = "Linux XMR miner payload (xmra64) used by multi-stage cron-based droppers"
        date = "2026-02-05"
        yarahub_reference_md5 = "3d4ebdfc02146e6df1784a4ebd7621ff"
        yarahub_uuid = "5ec18f06-9675-403b-9ec0-fdf1e8444ac5"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
    strings:
        /* Miner identifier */
        $miner1 = "xmra64" ascii

        /* Common execution locations */
        $path1 = "/dev/shm" ascii
        $path2 = "/var/tmp" ascii
    condition:
        uint32(0) == 0x464c457f and
        filesize > 1MB and filesize < 5MB and
        $miner1 and
        1 of ($path*)
}

rule MAL_Linux_IoT_MultiArch_BotnetLoader_Generic {
    meta:
        author = "Anish Bogati"
        description = "Technique-based detection of IoT/Linux botnet loader shell scripts downloading binaries from numeric IPs, chmodding, and executing multi-architecture payloads"
        date = "2025-12-01"
        yarahub_reference_md5       = "e72fbbe6906052e1d8f3546644602849"
        yarahub_uuid                = "4b0e3b57-6d91-4c3a-8f5d-0d7c6b2ff101"
        yarahub_license             = "CC0 1.0"
        yarahub_rule_matching_tlp   = "TLP:WHITE"
        yarahub_rule_sharing_tlp    = "TLP:WHITE"
        reference                   = "MalwareBazaar sample lilin.sh"
        yarahub_reference_link      = "https://bazaar.abuse.ch/sample/8cc4dbecbbd2d5dcd4722a63b936a694893aefa99db815284117a325d19f2fdc/"
        reference_sha256            = "8cc4dbecbbd2d5dcd4722a63b936a694893aefa99db815284117a325d19f2fdc"
    strings:
        // --- Technique: Downloaders ---
        $wget1    = "wget http://" ascii
        $wget2    = "wget -q http://" ascii
        $bb_wget  = "busybox wget" ascii
        $curl1    = "curl -fsS" ascii
        $curl2    = "curl -fsSO http://" ascii

        // Numeric IPv4 URL with optional port and path
        $re_ip_http = /http:\/\/[0-9]{1,3}(\.[0-9]{1,3}){3}(:[0-9]{1,5})?\/[A-Za-z0-9._\-\/]+/ ascii

        // --- Technique: Make downloaded files executable ---
        $chmod1  = "chmod 777" ascii
        $chmod2  = "chmod +x" ascii

        // --- Multi-arch evidence in FILENAMES / EXTENSIONS ---
        // e.g. Fantazy.mips, rondo.armv7l, irannet.mipsel, *.x86_64, *.sparc, *.arc700, *.i686, *.spc
        $re_ext_arch = /\.(mips(el)?|arm(v[4567]l|5|6|7)?|x86(_64)?|m68k|ppc|sparc|spc|sh4|arc700|i[3456]86)\b/ ascii

        // --- Multi-arch evidence in EXECUTION lines ---
        // e.g. ./mips, ./x86_64, ./Fantazy.mips, ./irannet.mipsel, ./arm7, ./ppc
        $re_exec_arch = /\.\/[A-Za-z0-9._\-]*(mips(el)?|arm(v[4567]l|5|6|7)?|x86(_64)?|m68k|ppc|sparc|spc|sh4|arc700|i[3456]86)\b/ ascii
    condition:
        // Script-like file, not a binary
        filesize < 50KB and
        uint32(0) != 0x7F454C46 and  // ELF
        uint16(0) != 0x4D5A and      // MZ (PE)

        // 1) Downloader present
        ( $wget1 or $wget2 or $bb_wget or $curl1 or $curl2 ) and

        // 2) Numeric-IP HTTP URLs present
        #re_ip_http >= 1 and

        // 3) chmod to make payload executable
        ( $chmod1 or $chmod2 ) and

        // 4) Strong multi-arch evidence:
        //    sum of filename-arch matches + exec-arch matches >= 2
        ( #re_ext_arch + #re_exec_arch ) >= 2
}

rule RANSOM_ESXiArgs_Ransomware_Encryptor_Feb23 {
    meta:
        author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
        description = "Detects the ESXiArgs Ransomware 'encrypt' binary"
        reference = "https://www.secuinfra.com/en/techtalk/hide-your-hypervisor-analysis-of-esxiargs-ransomware/"
        date = "2023-02-07"
        tlp = "CLEAR"
        yarahub_reference_md5 = "87b010bc90cd7dd776fb42ea5b3f85d3"
        yarahub_uuid = "5eed9fd1-410e-4d38-a355-d89617398785"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_author_twitter = "@SI_FalconTeam"
    strings:
        // Sosemanuk Pseudo-Random Number Generator
        $sosemanuk_prng = {48 8b 45 f8 48 01 45 e0 48 8b 45 f8 48 29 45 d8 48 8b 45 e8 8b 90 80 00 00 00 48 8b 45 f8 01 c2 48 8b 45 e8 89 90 80 00 00 00}

        // Sosemanuk Multiplication Tables
        // based on Findcrypt3 rule https://github.com/polymorf/findcrypt-yara/blob/ad165a6b2bd5b56932657b96edffa851b5b00b15/findcrypt3.rules#L1522
        $sosemanuk_mul_a = {00 00 00 00 13 CF 9F E1 26 37 97 6B 35 F8 08 8A [992] DE 4D 5B B5 CD 82 C4 54 F8 7A CC DE EB B5 53 3F}
        $sosemanuk_mul_ia = {00 00 00 00 CD 40 0F 18 33 80 1E 30 FE C0 11 28 [992] 1C 65 E2 9E D1 25 ED 86 2F E5 FC AE E2 A5 F3 B6}

        $interpreter = "/lib64/ld-linux-x86-64.so.2"

        $debug0 = "encrypt_bytes: too big data"
        $debug1 = "Progress: %f"

        $help = "usage: encrypt <public_key> <file_to_encrypt> [<enc_step>] [<enc_size>] [<file_size>]"
    condition:
        uint32be(0x0) == 0x7F454C46
        and all of ($sosemanuk_*)
        and $interpreter
        and 2 of ($debug*)
        and $help
}

// For feedback or questions contact us at: github@eset.com
// https://github.com/eset/malware-ioc/
//
// These yara rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2018, ESET
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

private rule ssh_client : sshdoor {
    meta:
        description = "Signature to match the clean (or not) OpenSSH client (ssh)"
        author = "Marc-Etienne M.Leveille"
        email  = "leveille@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $usage = "usage: ssh ["
        $old_version = "-L listen-port:host:port"

    condition:
        $usage or $old_version
}

private rule ssh_daemon : sshdoor {
    meta:
        description = "Signature to match the clean (or not) OpenSSH daemon (sshd)"
        author = "Marc-Etienne M.Leveille"
        email  = "leveille@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $usage = "usage: sshd ["
        $old_version = "Listen on the specified port (default: 22)"

    condition:
        $usage or $old_version
}

private rule ssh_add : sshdoor {
    meta:
        description = "Signature to match the clean (or not) OpenSSH add (ssh-add)"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $usage = "usage: %s [options] [file ...]\n"
        $log = "Could not open a connection to your authentication agent.\n"

    condition:
        $usage and $log
}

private rule ssh_agent : sshdoor {
    meta:
        description = "Signature to match the clean (or not) OpenSSH agent (ssh-agent)"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $usage = "usage: %s [options] [command [arg ...]]"

    condition:
        $usage
}

private rule ssh_askpass : sshdoor {
    meta:
        description = "Signature to match the clean (or not) OpenSSH daemon (sshd)"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $pass = "Enter your OpenSSH passphrase:"
        $log = "Could not grab %s. A malicious client may be eavesdropping on you"

    condition:
        $pass and $log
}

private rule ssh_keygen : sshdoor {
    meta:
        description = "Signature to match the clean (or not) OpenSSH keygen (ssh-keygen)"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $pass = "Enter new passphrase (empty for no passphrase):"
        $log = "revoking certificates by key ID requires specification of a CA key"

    condition:
        $pass and $log
}

private rule ssh_keyscan : sshdoor {
    meta:
        description = "Signature to match the clean (or not) OpenSSH keyscan (ssh-keyscan)"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $usage = "usage: %s [-46Hv] [-f file] [-p port] [-T timeout] [-t type]"

    condition:
        $usage
}

private rule ssh_binary : sshdoor {
    meta:
        description = "Signature to match any clean (or not) SSH binary"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"

    condition:
        ssh_client or ssh_daemon or ssh_add or ssh_askpass or ssh_keygen or ssh_keyscan
}

private rule stack_string {
    meta:
        description = "Rule to detect use of string-stacking"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        // single byte offset from base pointer
        $bp = /(\xC6\x45.{2}){25}/
        // dword ss with single byte offset from base pointer
        $bp_dw = /(\xC7\x45.{5}){20}/
        // 4-bytes offset from base pointer
        $bp_off = /(\xC6\x85.{5}){25}/
        // single byte offset from stack pointer
        $sp = /(\xC6\x44\x24.{2}){25}/
        // 4-bytes offset from stack pointer
        $sp_off = /(\xC6\x84\x24.{5}){25}/

    condition:
        any of them
}

rule abafar {
    meta:
        description = "Rule to detect Abafar family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $log_c =  "%s:%s@%s"
        $log_d =  "%s:%s from %s"

    condition:
        ssh_binary and any of them
}

rule akiva {
    meta:
        description = "Rule to detect Akiva family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $log = /(To|From):\s(%s\s\-\s)?%s:%s\n/

    condition:
        ssh_binary and $log
}

rule alderaan {
    meta:
        description = "Rule to detect Alderaan family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $log = /login\s(in|at):\s(%s\s)?%s:%s\n/

    condition:
        ssh_binary and $log
}

rule ando {
    meta:
        description = "Rule to detect Ando family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $s1 = "%s:%s\n"
        $s2 = "HISTFILE"
        $i = "fopen64"
        $m1 = "cat "
        $m2 = "mail -s"

    condition:
        ssh_binary and all of ($s*) and ($i or all of ($m*))
}

rule anoat {
    meta:
        description = "Rule to detect Anoat family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $log = "%s at: %s | user: %s, pass: %s\n"

    condition:
        ssh_binary and $log
}

rule atollon {
    meta:
        description = "Rule to detect Atollon family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $f1 = "PEM_read_RSA_PUBKEY"
        $f2 = "RAND_add"
        $log = "%s:%s"
        $rand = "/dev/urandom"

    condition:
        ssh_binary and stack_string and all of them
}

rule batuu {
    meta:
        description = "Rule to detect Batuu family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $args = "ssh: ~(av[%d]: %s\n)"
        $log = "readpass: %s\n"

    condition:
        ssh_binary and any of them
}

rule bespin {
    meta:
        description = "Rule to detect Bespin family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $log1 = "%Y-%m-%d %H:%M:%S"
        $log2 = "%s %s%s"
        $log3 = "[%s]"

    condition:
        ssh_binary and all of them
}

rule bonadan {
    meta:
        description = "Rule to detect Bonadan family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $s1 = "g_server"
        $s2 = "mine.sock"
        $s3 = "tspeed"
        $e1 = "6106#x=%d#%s#%s#speed=%s"
        $e2 = "usmars.mynetgear.com"
        $e3 = "user=%s#os=%s#eip=%s#cpu=%s#mem=%s"

    condition:
        ssh_binary and any of them
}

rule borleias {
    meta:
        description = "Rule to detect Borleias family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $log = "%Y-%m-%d %H:%M:%S [%s]"

    condition:
        ssh_binary and all of them
}

rule chandrila {
    meta:
        description = "Rule to detect Chandrila family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $log = "S%s %s:%s"
        $magic = { 05 71 92 7D }

    condition:
        ssh_binary and all of them
}

rule coruscant {
    meta:
        description = "Rule to detect Coruscant family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $s1 = "%s:%s@%s\n"
        $s2 = "POST"
        $s3 = "HTTP/1.1"

    condition:
        ssh_binary and all of them
}

rule crait {
    meta:
        description = "Signature to detect Crait family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $i1 = "flock"
        $i2 = "fchmod"
        $i3 = "sendto"

    condition:
        ssh_binary and 2 of them
}

rule endor {
    meta:
        description = "Rule to detect Endor family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $u = "user: %s"
        $p = "password: %s"

    condition:
        ssh_binary and $u and $p in (@u..@u+20)
}

rule jakuu {
    meta:
        description = "Rule to detect Jakuu family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        notes = "Strings can be encrypted"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $dec = /GET\s\/\?(s|c)id=/
        $enc1 = "getifaddrs"
        $enc2 = "usleep"
        $ns = "gethostbyname"
        $log = "%s:%s"
        $rc4 = { A1 71 31 17 11 1A 22 27 55 00 66 A3 10 FE C2 10 22 32 6E 95 90 84 F9 11 73 62 95 5F 4D 3B DB DC }

    condition:
        ssh_binary and $log and $ns and ($dec or all of ($enc*) or $rc4)
}

rule kamino {
    meta:
        description = "Rule to detect Kamino family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $s1 = "/var/log/wtmp"
        $s2 = "/var/log/secure"
        $s3 = "/var/log/auth.log"
        $s4 = "/var/log/messages"
        $s5 = "/var/log/audit/audit.log"
        $s6 = "/var/log/httpd-access.log"
        $s7 = "/var/log/httpd-error.log"
        $s8 = "/var/log/xferlog"
        $i1 = "BIO_f_base64"
        $i2 = "PEM_read_bio_RSA_PUBKEY"
        $i3 = "srand"
        $i4 = "gethostbyname"

    condition:
        ssh_binary and 5 of ($s*) and 3 of ($i*)
}

rule kessel {
    meta:
        description = "Rule to detect Kessel family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $rc4 = "Xee5chu1Ohshasheed1u"
        $s1 = "ssh:%s:%s:%s:%s"
        $s2 = "sshkey:%s:%s:%s:%s:%s"
        $s3 = "sshd:%s:%s"
        $i1 = "spy_report"
        $i2 = "protoShellCMD"
        $i3 = "protoUploadFile"
        $i4 = "protoSendReport"
        $i5 = "tunRecvDNS"
        $i6 = "tunPackMSG"

    condition:
        ssh_binary and (2 of ($s*) or 2 of ($i*) or $rc4)
}

rule mimban {
    meta:
        description = "Rule to detect Mimban family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $s1 = "<|||%s|||%s|||%d|||>"
        $s2 = />\|\|\|%s\|\|\|%s\|\|\|\d\|\|\|%s\|\|\|%s\|\|\|%s\|\|\|%s\|\|\|</
        $s3 = "-----BEGIN PUBLIC KEY-----"
        $i1 = "BIO_f_base64"
        $i2 = "PEM_read_bio_RSA_PUBKEY"
        $i3 = "gethostbyname"

    condition:
        ssh_binary and 2 of ($s*) and 2 of ($i*)
}

rule ondaron {
    meta:
        description = "Rule to detect Ondaron family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $daemon = "user:password --> %s:%s\n"
        $client = /user(,|:)(a,)?password@host \-\-> %s(,|:)(b,)?%s@%s\n/

    condition:
        ssh_binary and ($daemon or $client)
}

rule polis_massa {
    meta:
        description = "Rule to detect Polis Massa family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $log = /\b\w+(:|\s-+>)\s%s(:%d)?\s\t(\w+)?:\s%s\s\t(\w+)?:\s%s/

    condition:
        ssh_binary and $log
}

rule quarren {
    meta:
        description = "Rule to detect Quarren family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $log = "h: %s, u: %s, p: %s\n"

    condition:
        ssh_binary and $log
}

rule M_Hunting_Exploit_Archive_2 {
    meta:
        author = "Mandiant"
        description = "Hunting rule looking for TAR archives with /tmp/ base64 encoded being part of filename of enclosed files"
        md5 = "0d67f50a0bf7a3a017784146ac41ada0"
    strings:
        $ustar = { 75 73 74 61 72 }
        $b64_tmp = "/tmp/" base64
    condition:
        filesize < 1MB and
        $ustar at 257 and
        for any i in (0 .. #ustar) : (
            $b64_tmp in (i * 512 .. i * 512 + 250)
        )
}

rule M_Hunting_Exploit_Archive_3 {
    meta:
        author = "Mandiant"
        description = "Hunting rule looking for TAR archive with openssl base64 encoded being part of filename of enclosed files"
        md5 = "0d67f50a0bf7a3a017784146ac41ada0"
    strings:
        $ustar = { 75 73 74 61 72 }
        $b64_openssl = "openssl" base64
    condition:
        filesize < 1MB and
        $ustar at 257 and
        for any i in (0 .. #ustar) : (
            $b64_openssl in (i * 512 .. i * 512 + 250)
        )
}

rule M_Hunting_Exploit_Archive_CVE_2023_2868 {
    meta:
        author = "Mandiant"
        description = "Hunting rule looking for TAR archive with single quote/backtick as start of filename of enclosed files. CVE-2023-2868"
        md5 = "0d67f50a0bf7a3a017784146ac41ada0"
    strings:
        $ustar = { 75 73 74 61 72 }
        $qb = "'`"
    condition:
        filesize < 1MB and
        $ustar at 257 and
        for any i in (0 .. #ustar) : (
            $qb at (@ustar[i] + 255)
        )
}

rule M_Hunting_Linux_SALTWATER_1 {
    meta:
        author = "Mandiant"
        description = "Hunting rule looking for strings observed in SALTWATER samples."
        md5 = "827d507aa3bde0ef903ca5dec60cdec8"
    strings:
        $s1 = { 71 75 69 74 0D 0A 00 00 00 33 8C 25 3D 9C 17 70 08 F9 0C 1A 41 71 55 36 1A 5C 4B 8D 29 7E 0D 78 }
        $s2 = { 00 8B D5 AD 93 B7 54 D5 00 33 8C 25 3D 9C 17 70 08 F9 0C 1A 41 71 55 36 1A 5C 4B 8D 29 7E 0D 78 }
        $s3 = { 71 75 69 74 0D 0A 00 00 00 12 8D 03 07 9C 17 92 08 F0 0C 9A 01 06 08 00 1A 0C 0B 8D 18 0A 0D 0A }
    condition:
        uint32(0) == 0x464c457f and any of them
}

rule M_Hunting_Linux_SALTWATER_2 {
    meta:
        author = "Mandiant"
        description = "Hunting rule looking for strings observed in SALTWATER samples."
        md5 = "827d507aa3bde0ef903ca5dec60cdec8"
    strings:
        $c1 = "TunnelArgs"
        $c2 = "DownloadChannel"
        $c3 = "UploadChannel"
        $c4 = "ProxyChannel"
        $c5 = "ShellChannel"
        $c6 = "MyWriteAll"
        $c7 = "MyReadAll"
        $c8 = "Connected2Vps"
        $c9 = "CheckRemoteIp"
        $c10 = "GetFileSize"
        $s1 = "[-] error: popen failed"
        $s2 = "/home/product/code/config/ssl_engine_cert.pem"
        $s3 = "libbindshell.so"
    condition:
        uint32(0) == 0x464c457f and (any of ($s*) or 4 of ($c*))
}

rule FE_Hunting_Linux_Funchook_FEBeta {
    meta:
        author = "Mandiant"
        description = "Hunting rule looking for strings observed in Funchook library - https://github.com/kubo/funchook"
        md5 = "827d507aa3bde0ef903ca5dec60cdec8"
    strings:
        $f = "funchook_"
        $s1 = "Enter funchook_create()"
        $s2 = "Leave funchook_create() => %p"
        $s3 = "Enter funchook_prepare(%p, %p, %p)"
        $s4 = "Leave funchook_prepare(..., [%p->%p],...) => %d"
        $s5 = "Enter funchook_install(%p, 0x%x)"
        $s6 = "Leave funchook_install() => %d"
        $s7 = "Enter funchook_uninstall(%p, 0x%x)"
        $s8 = "Leave funchook_uninstall() => %d"
        $s9 = "Enter funchook_destroy(%p)"
        $s10 = "Leave funchook_destroy() => %d"
        $s11 = "Could not modify already-installed funchook handle."
        $s12 = "  change %s address from %p to %p"
        $s13 = "  link_map addr=%p, name=%s"
        $s14 = "  ELF type is neither ET_EXEC nor ET_DYN."
        $s15 = "  not a valid ELF module %s."
        $s16 = "Failed to protect memory %p (size=%"
        $s17 = "  protect memory %p (size=%"
        $s18 = "Failed to unprotect memory %p (size=%"
        $s19 = "  unprotect memory %p (size=%"
        $s20 = "Failed to unprotect page %p (size=%"
        $s21 = "  unprotect page %p (size=%"
        $s22 = "Failed to protect page %p (size=%"
        $s23 = "  protect page %p (size=%"
        $s24 = "Failed to deallocate page %p (size=%"
        $s25 = " deallocate page %p (size=%"
        $s26 = "  allocate page %p (size=%"
        $s27 = "  try to allocate %p but %p (size=%"
        $s28 = "  allocate page %p (size=%"
        $s29 = "Could not find a free region near %p"
        $s30 = "  -- Use address %p or %p for function %p"
    condition:
        uint32(0) == 0x464c457f and (#f > 5 or 4 of ($s*))
}

rule M_Hunting_Linux_SEASPY_1 {
    meta:
        author = "Mandiant"
        description = "Hunting rule looking for strings observed in SEASPY samples."
        md5 = "4ca4f582418b2cc0626700511a6315c0"
    strings:
        $s1 = "usage: ./BarracudaMailService <Network-Interface>. e.g.: ./BarracudaMailService eth0"
        $s2 = "NO port code" 
        $s3 = "pcap_lookupnet: %s"
        $s4 = "Child process id:%d"
        $s5 = "[*]Success!"
        $s6 = "enter open tty shell..."
    condition:
        uint32(0) == 0x464c457f and all of ($s*)
}

rule M_Hunting_Lua_SEASIDE_1 {
    meta:
        author = "Mandiant"
        description = "Hunting rule looking for strings observed in SEASIDE samples."
        md5 = "cd2813f0260d63ad5adf0446253c2172"
    strings:
        $s1 = "function on_helo()"
        $s2 = "local bindex,eindex = string.find(helo,'.onion')" 
        $s3 = "helosend = 'pd'..' '..helosend" 
        $s4 = "os.execute(helosend)" 
    condition:
        (filesize < 1MB) and all of ($s*)
}

rule M_Hunting_SKIPJACK_1 {
    meta:
        author = "Mandiant"
        description = "Hunting rule looking for strings observed in SKIPJACK installation script."
        md5 = "e4e86c273a2b67a605f5d4686783e0cc"
    strings:
        $str1 = "hdr:name() == 'Content-ID'" base64
        $str2 = "hdr:body() ~= nil" base64
        $str3 = "string.match(hdr:body(),\"^[%w%+/=\\r\\n]+$\")" base64
        $str4 = "openssl aes-256-cbc" base64
        $str5 = "mod_content.lua" 
        $str6 = "#!/bin/sh" 
    condition:
        all of them
}

rule M_Hunting_Lua_SKIPJACK_2 {
    meta:
        author = "Mandiant"
        description = "Hunting rule looking for strings observed in SKIPJACK samples."
        md5 = "87847445f9524671022d70f2a812728f"
    strings:
        $str1 = "hdr:name() == 'Content-ID'" 
        $str2 = "hdr:body() ~= nil" 
        $str3 = "string.match(hdr:body(),\"^[%w%+/=\\r\\n]+$\")" 
        $str4 = "openssl aes-256-cbc" 
        $str5 = "| base64 -d| sh 2>" 
    condition:
        all of them
}

rule M_Hunting_Lua_SEASPRAY_1 {
    meta:
        author = "Mandiant"
        description = "Hunting rule looking for strings observed in SEASPRAY samples."
        md5 = "35cf6faf442d325961935f660e2ab5a0"
    strings:
        $str1 = "string.find(attachment:filename(),'obt075') ~= nil" 
        $str2 = "os.execute('cp '..tostring(tmpfile)..' /tmp/'..attachment:filename())" 
        $str3 = "os.execute('rverify'..' /tmp/'..attachment:filename())" 
    condition:
        all of them
}

rule M_Hunting_Linux_WHIRLPOOL_1 {
    meta:
        author = "Mandiant"
        description = "Hunting rule looking for strings observed in WHIRLPOOL samples."
        md5 = "177add288b289d43236d2dba33e65956"
    strings:
        $s1 = "error -1 exit" fullword
        $s2 = "create socket error: %s(error: %d)\n" fullword
        $s3 = "connect error: %s(error: %d)\n" fullword
        $s4 = {C7 00 20 32 3E 26 66 C7 40 04 31 00}
        $c1 = "plain_connect" fullword
        $c2 = "ssl_connect" fullword
        $c3 = "SSLShell.c" fullword
    condition:
        filesize < 15MB and uint32(0) == 0x464c457f and (all of ($s*) or all of ($c*))
}

rule IOT_DDoS_tengu_sample {
   meta:
       description = "Mirai-derived Linux DDoS botnet: DGA+AEAD C2, proxy, Android/IPFS dropper, watchdog/reboot bricking"
       sha256 = "897226af37990fa60f25fea00b0509faa0e78d8bee10875c23b9b6ab0b8faed9"
       author = "Nozomi Networks Labs"
       date = "2026-07-07"

   strings:
       $masq1 = "[kworker/%d:%d]" ascii
       $masq2 = "/usr/lib/systemd/systemd-journald" ascii
       $masq3 = "/dev/shm/.journal" ascii
       $brick = "ELFOOD" ascii
       $svc1  = "chud-daemon" ascii
       $svc2  = "chud-watchdog" ascii
       $svc3  = "chud-scheduler" ascii
       $tengu = "/etc/init.d/tengu" ascii
       $upd   = "/tmp/.up" ascii
       $prox  = "/tmp/.proxy.pid" ascii
       $ipfs  = "GET /ipfs/%s HTTP/1.0" ascii
       $apk1  = "aapt dump badging '%s' 2>/dev/null" ascii
       $apk2  = "am start -n '%s/.MainActivity' 2>/dev/null" ascii
       $cron  = "* * * * * root [ -x /proc/self/exe ] && /proc/self/exe" ascii
       $wd    = "/dev/watchdog0" ascii
       $tsrc  = "TSource Engine Query" ascii

   condition:
       uint32(0) == 0x464c457f and 4 of them
}

rule LinuxFile_Backdoor {
    meta:
        description = "Detects the incident-specific linuxFile backdoor build"
        author = "QUIRSO Threat Research"
        date = "2026-08-14"
        sha256 = "2086954b8c286919f75bf0db762d4f16a5b6c48f7063c971cc751fe28f54bcdc"
        c2 = "intel.se9ly9upbhay.shop:8080 (XOR-obfuscated in binary)"
        confidence = "high"

    strings:
        $identity = "bd5275c6199dec0afb88972168d4ff6e895e832c579594798b94f7bdd7184c1180836c98f18fe2040ea382e556c0c9f88fcff0e5fb0eaa26330b028c1667722f" ascii

        $protocol_1 = "X3DH-SESSION" ascii
        $protocol_2 = "REGISTERED:OK:" ascii
        $protocol_3 = "expected REGISTERED, got: " ascii
        $crypto     = "src/signal_crypto.rs" ascii

        $reconnect  = "reconnect in " ascii
        $shell      = "/bin/sh" ascii
        $cron_1     = "crontab fallback: " ascii
        $cron_2     = "spawn crontab failed: " ascii
        $systemd_1  = "Environment=NO_DAEMON=1" ascii
        $systemd_2  = "Description=System Service" ascii
        $systemd_3  = "/etc/systemd/system/" ascii

    condition:
        uint32(0) == 0x464c457f and
        uint16(18) == 0x003e and
        filesize > 500KB and filesize < 2MB and
        $identity and
        3 of ($protocol_*) and
        $crypto and $reconnect and $shell and
        2 of ($cron_*, $systemd_*)
}

rule BirdTroy_Linux {
    meta:
        description = "BirdTroy - Go-based Linux backdoor (Bird/module namespace)"
        date = "2026-05-28"
        hash1 = "ca98a51cebdc802d255030b4baa44ca0"
        hash2 = "c2e37232556357944a04edf1dec3934b"
    strings:
        $ns1 = "Bird/module/packet."
        $ns2 = "Bird/module/autorun."
        $ns3 = "Bird/module/shell."
        $ns4 = "Bird/module/protocol."
        $resp1 = "success upload file"
        $resp2 = "usege: sleep [hour]"
        $resp3 = "delete success"
        $code_bswap = { 8B 00 0F C8 48 81 C4 B8 00 00 00 5D C3 }
    condition:
        uint32(0) == 0x464C457F and (
            3 of ($ns*) or
            (2 of ($resp*) and 1 of ($ns*)) or
            ($code_bswap and 1 of ($ns*))
        )
}

rule DriveTroy_Linux {
    meta:
        description = "DriveTroy - Go-based Linux backdoor abusing Google Drive"
        date = "2026-05-28"
        hash = "a452a860f973c7a43ea804c17e9427d2"
    strings:
        $ns1 = "jira/payload/gdrive."
        $ns2 = "jira/payload/common."
        $ns3 = "jira/payload/common/transfer."
        $svc1 = "cachelogd"
        $svc2 = "cachemond"
        $svc3 = "monlogd"
        $build = "C:/Users/jira/go/src/jira/payload/"
        $code_tail = { 48 C7 C3 FC FF FF FF B9 02 00 00 00 0F 1F 00 E8 }
        $code_shadow = { 48 8D 05 ?? ?? ?? ?? BB 0B 00 00 00 E8 ?? ?? ?? ?? 48 85 FF 74 07 }
    condition:
        uint32(0) == 0x464C457F and (
            2 of ($ns*) or
            $build or
            2 of ($svc*) or
            ($code_tail and $code_shadow)
        )
}

rule Gomir_Linux {
    meta:
        description = "Gomir - Go-based Linux backdoor (Github-Lin/Main/Kernel)"
        date = "2026-06-02"
        hash1 = "b1c72139f2cdd9419562369fc6ced4fc"
        hash2 = "84e9b066bebd49036b7fc71b5f5f8d83"
        hash3 = "e911f8f7c49476806ada37f3ebb7a28a"
        hash4 = "aa61e76255a6e13313439655bc02bdf5"
    strings:
        $ns1 = "local.github.com/Github-Lin/Main/Kernel."
        $ns2 = "local.github.com/Github-Lin/Main/exe"
        $cmd1 = "Not implemented on Linux!"
        $cmd2 = "Unknown Command!\r\n"
        $cmd3 = "Invalid Param!\r\n"
        $persist1 = "/etc/systemd/system/rsyslogd.service"
        $persist2 = "systemctl reenable rsyslogd"
        $code_mod255 = { 48 B8 81 80 80 80 80 80 80 80 49 89 D3 49 F7 E8 }
        $code_sleep = { 48 B8 00 10 A5 D4 E8 00 00 00 E8 ?? ?? ?? ?? EB EF }
        $code_uid = { 48 83 F9 05 7D 3B 0F B6 74 0C 46 89 F7 40 C0 EE 04 }
    condition:
        uint32(0) == 0x464C457F and (
            1 of ($ns*) or
            (2 of ($cmd*) and 1 of ($persist*)) or
            $code_mod255 or
            ($code_sleep and 1 of ($ns*, $persist*)) or
            ($code_uid and 1 of ($ns*, $persist*))
        )
}

rule EXT_WEBSHELL_PHP_Generic {
   meta:
      description = "php webshell having some kind of input and some kind of payload. restricted to small files or big ones including suspicious strings"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Arnim Rupp (https://github.com/ruppde)"
      reference = "Internal Research"
      score = 70
      date = "2021-01-14"
      modified = "2026-03-09"
      hash = "bee1b76b1455105d4bfe2f45191071cf05e83a309ae9defcf759248ca9bceddd"
      hash = "6bf351900a408120bee3fc6ea39905c6a35fe6efcf35d0a783ee92062e63a854"
      hash = "e3b4e5ec29628791f836e15500f6fdea19beaf3e8d9981c50714656c50d3b365"
      hash = "00813155bf7f5eb441e1619616a5f6b21ae31afc99caa000c4aafd54b46c3597"
      hash = "e31788042d9cdeffcb279533b5a7359b3beb1144f39bacdd3acdef6e9b4aff25"
      hash = "36b91575a08cf40d4782e5aebcec2894144f1e236a102edda2416bc75cbac8dd"
      hash = "a34154af7c0d7157285cfa498734cfb77662edadb1a10892eb7f7e2fb5e2486c"
      hash = "791a882af2cea0aa8b8379791b401bebc235296858266ddb7f881c8923b7ea61"
      hash = "9a8ab3c225076a26309230d7eac7681f85b271d2db22bf5a190adbf66faca2e6"
      hash = "0d3ee83adc9ebf8fb1a8c449eed5547ee5e67e9a416cce25592e80963198ae23"
      hash = "3d8708609562a27634df5094713154d8ca784dbe89738e63951e12184ff07ad6"
      hash = "70d64d987f0d9ab46514abcc868505d95dbf458387f858b0d7580e4ee8573786"
      hash = "259b3828694b4d256764d7d01b0f0f36ca0526d5ee75e134c6a754d2ab0d1caa"
      hash = "04d139b48d59fa2ef24fb9347b74fa317cb05bd8b7389aeb0a4d458c49ea7540"
      hash = "58d0e2ff61301fe0c176b51430850239d3278c7caf56310d202e0cdbdde9ac3f"
      hash = "731f36a08b0e63c63b3a2a457667dfc34aa7ff3a2aee24e60a8d16b83ad44ce2"
      hash = "e4ffd4ec67762fe00bb8bd9fbff78cffefdb96c16fe7551b5505d319a90fa18f"
      hash = "fa00ee25bfb3908808a7c6e8b2423c681d7c52de2deb30cbaea2ee09a635b7d4"
      hash = "98c1937b9606b1e8e0eebcb116a784c9d2d3db0039b21c45cba399e86c92c2fa"
      hash = "e9423ad8e51895db0e8422750c61ef4897b3be4292b36dba67d42de99e714bff"
      hash = "7a16311a371f03b29d5220484e7ecbe841cfaead4e73c17aa6a9c23b5d94544d"
      hash = "7ca5dec0515dd6f401cb5a52c313f41f5437fc43eb62ea4bcc415a14212d09e9"
      hash = "3de8c04bfdb24185a07f198464fcdd56bb643e1d08199a26acee51435ff0a99f"
      hash = "63297f8c1d4e88415bc094bc5546124c9ed8d57aca3a09e36ae18f5f054ad172"
      hash = "a09dcf52da767815f29f66cb7b03f3d8c102da5cf7b69567928961c389eac11f"
      hash = "d9ae762b011216e520ebe4b7abcac615c61318a8195601526cfa11bbc719a8f1"
      hash = "dd5d8a9b4bb406e0b8f868165a1714fe54ffb18e621582210f96f6e5ae850b33"
      id = "ce3c93a5-3088-5e7e-a0d4-8bea18cf9cc3"
   strings:
      $wfp_tiny1 = "escapeshellarg" fullword
      $wfp_tiny2 = "addslashes" fullword

      //strings from private rule php_false_positive_tiny
      // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
      //$gfp_tiny1 = "addslashes" fullword
      //$gfp_tiny2 = "escapeshellarg" fullword
      $gfp_tiny3 = "include \"./common.php\";"  // xcache
      $gfp_tiny4 = "assert('FALSE');"
      $gfp_tiny5 = "assert(false);"
      $gfp_tiny6 = "assert(FALSE);"
      $gfp_tiny7 = "assert('array_key_exists("
      $gfp_tiny8 = "echo shell_exec($aspellcommand . ' 2>&1');"
      $gfp_tiny9 = "throw new Exception('Could not find authentication source with id ' . $sourceId);"
      $gfp_tiny10 = "return isset( $_POST[ $key ] ) ? $_POST[ $key ] : ( isset( $_REQUEST[ $key ] ) ? $_REQUEST[ $key ] : $default );"
      $gfp_tiny11 = "; This is the recommended, PHP 4-style version of the php.ini-dist file"

      //strings from private rule capa_php_old_safe
      $php_short = "<?" wide ascii
      // prevent xml and asp from hitting with the short tag
      $no_xml1 = "<?xml version" nocase wide ascii
      $no_xml2 = "<?xml-stylesheet" nocase wide ascii
      $no_asp1 = "<%@LANGUAGE" nocase wide ascii
      $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
      $no_pdf = "<?xpacket"

      // of course the new tags should also match
      // already matched by "<?"
      $php_new1 = /<\?=[^?]/ wide ascii
      $php_new2 = "<?php" nocase wide ascii
      $php_new3 = "<script language=\"php" nocase wide ascii

      //strings from private rule capa_php_input
      $inp1 = "php://input" wide ascii
      $inp2 = /_GET\s?\[/ wide ascii
      // for passing $_GET to a function
      $inp3 = /\(\s?\$_GET\s?\)/ wide ascii
      $inp4 = /_POST\s?\[/ wide ascii
      $inp5 = /\(\s?\$_POST\s?\)/ wide ascii
      $inp6 = /_REQUEST\s?\[/ wide ascii
      $inp7 = /\(\s?\$_REQUEST\s?\)/ wide ascii
      $inp8 = /\(\s?\$_HEADERS\s?[\)\[]/ wide ascii
      // PHP automatically adds all the request headers into the $_SERVER global array, prefixing each header name by the "HTTP_" string, so e.g. @eval($_SERVER['HTTP_CMD']) will run any code in the HTTP header CMD
      $inp15 = "_SERVER['HTTP_" wide ascii
      $inp16 = "_SERVER[\"HTTP_" wide ascii
      $inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ wide ascii
      $inp18 = "array_values($_SERVER)" wide ascii
      $inp19 = /file_get_contents\("https?:\/\// wide ascii
      $inp20 = "TSOP_" wide ascii

      //strings from private rule capa_php_payload
      // \([^)] to avoid matching on e.g. eval() in comments
      $cpayload1 = /\beval[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
      $cpayload2 = /\bexec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
      $cpayload3 = /\bshell_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
      $cpayload4 = /\bpassthru[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
      $cpayload5 = /\bsystem[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
      $cpayload6 = /\bpopen[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
      $cpayload7 = /\bproc_open[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
      $cpayload8 = /\bpcntl_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
      $cpayload9 = /\bassert[\n\t ]{0,500}\([^)0]/ nocase wide ascii
      $cpayload10 = /\bpreg_replace[\n\t ]{0,500}\([^\)]{1,100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
      $cpayload12 = /\bmb_ereg_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
      $cpayload13 = /\bmb_eregi_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
      $cpayload20 = /\bcreate_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
      $cpayload21 = /\bReflectionFunction[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
      $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]{0,500}[,}\)]/ nocase wide ascii

      $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]{0,500}(\([^\)]|\/\*)/ nocase wide ascii
      $m_cpayload_preg_filter2 = "'|.{0,500}|e'" nocase wide ascii
      // TODO backticks

      //strings from private rule capa_gen_sus

      // these strings are just a bit suspicious, so several of them are needed, depending on filesize
      $gen_bit_sus1 = /:\s{0,20}eval}/ nocase wide ascii
      $gen_bit_sus2 = /\.replace\(\/\w\/g/ nocase wide ascii
      $gen_bit_sus6 = "self.delete"
      $gen_bit_sus9 = "\"cmd /c" nocase
      $gen_bit_sus10 = "\"cmd\"" nocase
      $gen_bit_sus11 = "\"cmd.exe" nocase
      $gen_bit_sus12 = "%comspec%" wide ascii
      $gen_bit_sus13 = "%COMSPEC%" wide ascii
      //TODO:$gen_bit_sus12 = ".UserName" nocase
      $gen_bit_sus18 = "Hklm.GetValueNames();" nocase
      // bonus string for proxylogon exploiting webshells
      $gen_bit_sus19 = "http://schemas.microsoft.com/exchange/" wide ascii
      $gen_bit_sus21 = "\"upload\"" wide ascii
      $gen_bit_sus22 = "\"Upload\"" wide ascii
      $gen_bit_sus23 = "UPLOAD" fullword wide ascii
      $gen_bit_sus24 = "fileupload" wide ascii
      $gen_bit_sus25 = "file_upload" wide ascii
      // own base64 or base32 func
      $gen_bit_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword wide ascii
      $gen_bit_sus29b = "abcdefghijklmnopqrstuvwxyz234567" fullword wide ascii
      $gen_bit_sus30 = "serv-u" wide ascii
      $gen_bit_sus31 = "Serv-u" wide ascii
      $gen_bit_sus32 = "Army" fullword wide ascii
      // single letter paramweter
      $gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword wide ascii
      $gen_bit_sus34 = "Content-Transfer-Encoding: Binary" wide ascii
      $gen_bit_sus35 = "crack" fullword wide ascii

      $gen_bit_sus44 = "<pre>" wide ascii
      $gen_bit_sus45 = "<PRE>" wide ascii
      $gen_bit_sus46 = "shell_" wide ascii
      //fp: $gen_bit_sus47 = "Shell" fullword wide ascii
      $gen_bit_sus50 = "bypass" wide ascii
      $gen_bit_sus52 = " ^ $" wide ascii
      $gen_bit_sus53 = ".ssh/authorized_keys" wide ascii
      $gen_bit_sus55 = /\w'\.'\w/ wide ascii
      $gen_bit_sus56 = /\w\"\.\"\w/ wide ascii
      $gen_bit_sus57 = "dumper" wide ascii
      $gen_bit_sus59 = "'cmd'" wide ascii
      $gen_bit_sus60 = "\"execute\"" wide ascii
      $gen_bit_sus61 = "/bin/sh" wide ascii
      $gen_bit_sus62 = "Cyber" wide ascii
      $gen_bit_sus63 = "portscan" fullword wide ascii
      //$gen_bit_sus64 = "\"command\"" fullword wide ascii
      //$gen_bit_sus65 = "'command'" fullword wide ascii
      $gen_bit_sus66 = "whoami" fullword wide ascii
      $gen_bit_sus67 = "$password='" fullword wide ascii
      $gen_bit_sus68 = "$password=\"" fullword wide ascii
      $gen_bit_sus69 = "$cmd" fullword wide ascii
      $gen_bit_sus70 = "\"?>\"." fullword wide ascii
      $gen_bit_sus71 = "Hacking" fullword wide ascii
      $gen_bit_sus72 = "hacking" fullword wide ascii
      $gen_bit_sus73 = ".htpasswd" wide ascii
      $gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/ wide ascii
      $gen_bit_sus75 = "uploaded" fullword wide ascii

      // very suspicious strings, one is enough
      $gen_much_sus7 = "Web Shell" nocase
      $gen_much_sus8 = "WebShell" nocase
      $gen_much_sus3 = "hidded shell"
      $gen_much_sus4 = "WScript.Shell.1" nocase
      $gen_much_sus5 = "AspExec"
      $gen_much_sus14 = "\\pcAnywhere\\" nocase
      $gen_much_sus15 = "antivirus" nocase
      $gen_much_sus16 = "McAfee" nocase
      $gen_much_sus17 = "nishang"
      $gen_much_sus18 = "\"unsafe" fullword wide ascii
      $gen_much_sus19 = "'unsafe" fullword wide ascii
      $gen_much_sus24 = "exploit" fullword wide ascii
      $gen_much_sus25 = "Exploit" fullword wide ascii
      $gen_much_sus26 = "TVqQAAMAAA" wide ascii
      $gen_much_sus30 = "Hacker" wide ascii
      $gen_much_sus31 = "HACKED" fullword wide ascii
      $gen_much_sus32 = "hacked" fullword wide ascii
      $gen_much_sus33 = "hacker" wide ascii
      $gen_much_sus34 = "grayhat" nocase wide ascii
      $gen_much_sus35 = "Microsoft FrontPage" wide ascii
      $gen_much_sus36 = "Rootkit" wide ascii
      $gen_much_sus37 = "rootkit" wide ascii
      $gen_much_sus38 = "/*-/*-*/" wide ascii
      $gen_much_sus39 = "u\"+\"n\"+\"s" wide ascii
      $gen_much_sus40 = "\"e\"+\"v" wide ascii
      $gen_much_sus41 = "a\"+\"l\"" wide ascii
      $gen_much_sus42 = "\"+\"(\"+\"" wide ascii
      $gen_much_sus43 = "q\"+\"u\"" wide ascii
      $gen_much_sus44 = "\"u\"+\"e" wide ascii
      $gen_much_sus45 = "/*//*/" wide ascii
      $gen_much_sus46 = "(\"/*/\"" wide ascii
      $gen_much_sus47 = "eval(eval(" wide ascii
      // self remove
      $gen_much_sus48 = "unlink(__FILE__)" wide ascii
      $gen_much_sus49 = "Shell.Users" wide ascii
      $gen_much_sus50 = "PasswordType=Regular" wide ascii
      $gen_much_sus51 = "-Expire=0" wide ascii
      $gen_much_sus60 = "_=$$_" wide ascii
      $gen_much_sus62 = "++;$" wide ascii
      $gen_much_sus63 = "++; $" wide ascii
      $gen_much_sus64 = "_.=$_" wide ascii
      $gen_much_sus70 = "-perm -04000" wide ascii
      $gen_much_sus71 = "-perm -02000" wide ascii
      $gen_much_sus72 = "grep -li password" wide ascii
      $gen_much_sus73 = "-name config.inc.php" wide ascii
      // touch without parameters sets the time to now, not malicious and gives fp
      $gen_much_sus75 = "password crack" wide ascii
      $gen_much_sus76 = "mysqlDll.dll" wide ascii
      $gen_much_sus77 = "net user" wide ascii
      $gen_much_sus80 = "fopen(\".htaccess\",\"w" wide ascii
      $gen_much_sus81 = /strrev\(['"]/ wide ascii
      $gen_much_sus82 = "PHPShell" fullword wide ascii
      $gen_much_sus821 = "PHP Shell" fullword wide ascii
      $gen_much_sus83 = "phpshell" fullword wide ascii
      $gen_much_sus84 = "PHPshell" fullword wide ascii
      $gen_much_sus87 = "deface" wide ascii
      $gen_much_sus88 = "Deface" wide ascii
      $gen_much_sus89 = "backdoor" wide ascii
      $gen_much_sus90 = "r00t" fullword wide ascii
      $gen_much_sus91 = "xp_cmdshell" fullword wide ascii
      $gen_much_sus92 = "str_rot13" fullword wide ascii

      //strings from private rule capa_php_payload_multiple
      // \([^)] to avoid matching on e.g. eval() in comments
      $cmpayload1 = /\beval[\t ]{0,500}\([^)]/ nocase wide ascii
      $cmpayload2 = /\bexec[\t ]{0,500}\([^)]/ nocase wide ascii
      $cmpayload3 = /\bshell_exec[\t ]{0,500}\([^)]/ nocase wide ascii
      $cmpayload4 = /\bpassthru[\t ]{0,500}\([^)]/ nocase wide ascii
      $cmpayload5 = /\bsystem[\t ]{0,500}\([^)]/ nocase wide ascii
      $cmpayload6 = /\bpopen[\t ]{0,500}\([^)]/ nocase wide ascii
      $cmpayload7 = /\bproc_open[\t ]{0,500}\([^)]/ nocase wide ascii
      $cmpayload8 = /\bpcntl_exec[\t ]{0,500}\([^)]/ nocase wide ascii
      $cmpayload9 = /\bassert[\t ]{0,500}\([^)0]/ nocase wide ascii
      $cmpayload10 = /\bpreg_replace[\t ]{0,500}\([^\)]{1,100}\/e/ nocase wide ascii
      $cmpayload11 = /\bpreg_filter[\t ]{0,500}\([^\)]{1,100}\/e/ nocase wide ascii
      $cmpayload12 = /\bmb_ereg_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
      $cmpayload20 = /\bcreate_function[\t ]{0,500}\([^)]/ nocase wide ascii
      $cmpayload21 = /\bReflectionFunction[\t ]{0,500}\([^)]/ nocase wide ascii

      $fp1 = "# Some examples from obfuscated malware:" ascii
      $fp2 = "{@see TFileUpload} for further details." ascii
   condition:
      filesize < 500KB
      and (
         any of ($inp*)
      )
      and (
         any of ($cpayload*) or
         all of ($m_cpayload_preg_filter*)
      )
      and (
         (
            (
               $php_short in (0..100) or
               $php_short in (filesize - 1000..filesize)
            )
            and not any of ($no_*)
         )
         or any of ($php_new*)
      )
      and
      ((filesize < 1000 and not any of ($wfp_tiny*)) or
         ((
               uint32be(0) == 0x47494638  // GIF8
               or (
                  filesize < 4KB and
                  (
                     1 of ($gen_much_sus*) or
                     2 of ($gen_bit_sus*)
                  )
               ) or (
                  filesize < 20KB and
                  (
                     2 of ($gen_much_sus*) or
                     3 of ($gen_bit_sus*)
                  )
               ) or (
                  filesize < 50KB and
                  (
                     2 of ($gen_much_sus*) or
                     4 of ($gen_bit_sus*)
                  )
               ) or (
                  filesize < 100KB and
                  (
                     2 of ($gen_much_sus*) or
                     6 of ($gen_bit_sus*)
                  )
               ) or (
                  filesize < 150KB and
                  (
                     3 of ($gen_much_sus*) or
                     7 of ($gen_bit_sus*)
                  )
               ) or (
                  filesize < 500KB and
                  (
                     4 of ($gen_much_sus*) or
                     8 of ($gen_bit_sus*)
                  )
               )
            )
            and
            (filesize > 5KB or not any of ($wfp_tiny*))) or
         (filesize < 500KB and (
               4 of ($cmpayload*)
            )
         )
      )
      and not (
         any of ($gfp_tiny*)
         or 1 of ($fp*)
      )
}


rule WEBSHELL_PHP_Generic_Callback {
    meta:
        description = "php webshell having some kind of input and using a callback to execute the payload. restricted to small files or would give lots of false positives"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/01/14"
        modified = "2023-09-18"
        score = 60
        hash = "e98889690101b59260e871c49263314526f2093f"
        hash = "63297f8c1d4e88415bc094bc5546124c9ed8d57aca3a09e36ae18f5f054ad172"
        hash = "81388c8cc99353cdb42572bb88df7d3bd70eefc748c2fa4224b6074aa8d7e6a2"
        hash = "27d3bfabc283d851b0785199da8b1b0384afcb996fa9217687274dd56a7b5f49"
        hash = "ee256d7cc3ceb2bf3a1934d553cdd36e3fbde62a02b20a1b748a74e85d4dbd33"
        hash = "4adc6c5373c4db7b8ed1e7e6df10a3b2ce5e128818bb4162d502056677c6f54a"
        hash = "1fe4c60ea3f32819a98b1725581ac912d0f90d497e63ad81ccf258aeec59fee3"
        hash = "2967f38c26b131f00276bcc21227e54ee6a71881da1d27ec5157d83c4c9d4f51"
        hash = "1ba02fb573a06d5274e30b2b05573305294497769414e964a097acb5c352fb92"
        hash = "f4fe8e3b2c39090ca971a8e61194fdb83d76fadbbace4c5eb15e333df61ce2a4"
        hash = "badda1053e169fea055f5edceae962e500842ad15a5d31968a0a89cf28d89e91"
        hash = "0a29cf1716e67a7932e604c5d3df4b7f372561200c007f00131eef36f9a4a6a2"
        hash = "51c2c8b94c4b8cce806735bcf6e5aa3f168f0f7addce47b699b9a4e31dc71b47"
        hash = "de1ef827bcd3100a259f29730cb06f7878220a7c02cee0ebfc9090753d2237a8"
        hash = "487e8c08e85774dfd1f5e744050c08eb7d01c6877f7d03d7963187748339e8c4"

        id = "e33dba84-bbeb-5955-a81b-2d2c8637fb48"
    strings:

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

        //strings from private rule php_false_positive_tiny
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        //$gfp_tiny1 = "addslashes" fullword
        //$gfp_tiny2 = "escapeshellarg" fullword
        $gfp_tiny3 = "include \"./common.php\";" // xcache
        $gfp_tiny4 = "assert('FALSE');"
        $gfp_tiny5 = "assert(false);"
        $gfp_tiny6 = "assert(FALSE);"
        $gfp_tiny7 = "assert('array_key_exists("
        $gfp_tiny8 = "echo shell_exec($aspellcommand . ' 2>&1');"
        $gfp_tiny9 = "throw new Exception('Could not find authentication source with id ' . $sourceId);"
        $gfp_tiny10= "return isset( $_POST[ $key ] ) ? $_POST[ $key ] : ( isset( $_REQUEST[ $key ] ) ? $_REQUEST[ $key ] : $default );"

        //strings from private rule capa_php_input
        $inp1 = "php://input" wide ascii
        $inp2 = /_GET\s?\[/ wide ascii
        // for passing $_GET to a function
        $inp3 = /\(\s?\$_GET\s?\)/ wide ascii
        $inp4 = /_POST\s?\[/ wide ascii
        $inp5 = /\(\s?\$_POST\s?\)/ wide ascii
        $inp6 = /_REQUEST\s?\[/ wide ascii
        $inp7 = /\(\s?\$_REQUEST\s?\)/ wide ascii
        // PHP automatically adds all the request headers into the $_SERVER global array, prefixing each header name by the "HTTP_" string, so e.g. @eval($_SERVER['HTTP_CMD']) will run any code in the HTTP header CMD
        $inp15 = "_SERVER['HTTP_" wide ascii
        $inp16 = "_SERVER[\"HTTP_" wide ascii
        $inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ wide ascii
        $inp18 = "array_values($_SERVER)" wide ascii
        $inp19 = /file_get_contents\("https?:\/\// wide ascii

        // TODO: arraywalk \n /*
        //strings from private rule capa_php_callback
        // the end is 1. ( followed by anything but a direct closing ) 2. /* for the start of an obfuscation comment
        $callback1 = /\bob_start[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback2 = /\barray_diff_uassoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback3 = /\barray_diff_ukey[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback4 = /\barray_filter[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback5 = /\barray_intersect_uassoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback6 = /\barray_intersect_ukey[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback7 = /\barray_map[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback8 = /\barray_reduce[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback9 = /\barray_udiff_assoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback10 = /\barray_udiff_uassoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback11 = /\barray_udiff[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback12 = /\barray_uintersect_assoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback13 = /\barray_uintersect_uassoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback14 = /\barray_uintersect[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback15 = /\barray_walk_recursive[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback16 = /\barray_walk[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback17 = /\bassert_options[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback18 = /\buasort[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback19 = /\buksort[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback20 = /\busort[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback21 = /\bpreg_replace_callback[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback22 = /\bspl_autoload_register[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback23 = /\biterator_apply[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback24 = /\bcall_user_func[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback25 = /\bcall_user_func_array[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback26 = /\bregister_shutdown_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback27 = /\bregister_tick_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback28 = /\bset_error_handler[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback29 = /\bset_exception_handler[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback30 = /\bsession_set_save_handler[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback31 = /\bsqlite_create_aggregate[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback32 = /\bsqlite_create_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback33 = /\bmb_ereg_replace_callback[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii

        $m_callback1 = /\bfilter_var[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $m_callback2 = "FILTER_CALLBACK" fullword wide ascii

        $cfp1 = /ob_start\(['\"]ob_gzhandler/ nocase wide ascii
        $cfp2 = "IWPML_Backend_Action_Loader" ascii wide
        $cfp3 = "<?phpclass WPML" ascii

        //strings from private rule capa_gen_sus

        // these strings are just a bit suspicious, so several of them are needed, depending on filesize
        $gen_bit_sus1  = /:\s{0,20}eval}/ nocase wide ascii
        $gen_bit_sus2  = /\.replace\(\/\w\/g/ nocase wide ascii
        $gen_bit_sus6  = "self.delete"
        $gen_bit_sus9  = "\"cmd /c" nocase
        $gen_bit_sus10 = "\"cmd\"" nocase
        $gen_bit_sus11 = "\"cmd.exe" nocase
        $gen_bit_sus12 = "%comspec%" wide ascii
        $gen_bit_sus13 = "%COMSPEC%" wide ascii
        //TODO:$gen_bit_sus12 = ".UserName" nocase
        $gen_bit_sus18 = "Hklm.GetValueNames();" nocase
        // bonus string for proxylogon exploiting webshells
        $gen_bit_sus19 = "http://schemas.microsoft.com/exchange/" wide ascii
        $gen_bit_sus21 = "\"upload\"" wide ascii
        $gen_bit_sus22 = "\"Upload\"" wide ascii
        $gen_bit_sus23 = "UPLOAD" fullword wide ascii
        $gen_bit_sus24 = "fileupload" wide ascii
        $gen_bit_sus25 = "file_upload" wide ascii
        // own base64 or base32 func
        $gen_bit_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword wide ascii
        $gen_bit_sus29b = "abcdefghijklmnopqrstuvwxyz234567" fullword wide ascii
        $gen_bit_sus30 = "serv-u" wide ascii
        $gen_bit_sus31 = "Serv-u" wide ascii
        $gen_bit_sus32 = "Army" fullword wide ascii
        // single letter paramweter
        $gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword wide ascii
        $gen_bit_sus34 = "Content-Transfer-Encoding: Binary" wide ascii
        $gen_bit_sus35 = "crack" fullword wide ascii

        $gen_bit_sus44 = "<pre>" wide ascii
        $gen_bit_sus45 = "<PRE>" wide ascii
        $gen_bit_sus46 = "shell_" wide ascii
        //fp: $gen_bit_sus47 = "Shell" fullword wide ascii
        $gen_bit_sus50 = "bypass" wide ascii
        $gen_bit_sus52 = " ^ $" wide ascii
        $gen_bit_sus53 = ".ssh/authorized_keys" wide ascii
        $gen_bit_sus55 = /\w'\.'\w/ wide ascii
        $gen_bit_sus56 = /\w\"\.\"\w/ wide ascii
        $gen_bit_sus57 = "dumper" wide ascii
        $gen_bit_sus59 = "'cmd'" wide ascii
        $gen_bit_sus60 = "\"execute\"" wide ascii
        $gen_bit_sus61 = "/bin/sh" wide ascii
        $gen_bit_sus62 = "Cyber" wide ascii
        $gen_bit_sus63 = "portscan" fullword wide ascii
        //$gen_bit_sus64 = "\"command\"" fullword wide ascii
        //$gen_bit_sus65 = "'command'" fullword wide ascii
        $gen_bit_sus66 = "whoami" fullword wide ascii
        $gen_bit_sus67 = "$password='" fullword wide ascii
        $gen_bit_sus68 = "$password=\"" fullword wide ascii
        $gen_bit_sus69 = "$cmd" fullword wide ascii
        $gen_bit_sus70 = "\"?>\"." fullword wide ascii
        $gen_bit_sus71 = "Hacking" fullword wide ascii
        $gen_bit_sus72 = "hacking" fullword wide ascii
        $gen_bit_sus73 = ".htpasswd" wide ascii
        $gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/ wide ascii

        // very suspicious strings, one is enough
        $gen_much_sus7  = "Web Shell" nocase
        $gen_much_sus8  = "WebShell" nocase
        $gen_much_sus3  = "hidded shell"
        $gen_much_sus4  = "WScript.Shell.1" nocase
        $gen_much_sus5  = "AspExec"
        $gen_much_sus14 = "\\pcAnywhere\\" nocase
        $gen_much_sus15 = "antivirus" nocase
        $gen_much_sus16 = "McAfee" nocase
        $gen_much_sus17 = "nishang"
        $gen_much_sus18 = "\"unsafe" fullword wide ascii
        $gen_much_sus19 = "'unsafe" fullword wide ascii
        $gen_much_sus24 = "exploit" fullword wide ascii
        $gen_much_sus25 = "Exploit" fullword wide ascii
        $gen_much_sus26 = "TVqQAAMAAA" wide ascii
        $gen_much_sus30 = "Hacker" wide ascii
        $gen_much_sus31 = "HACKED" fullword wide ascii
        $gen_much_sus32 = "hacked" fullword wide ascii
        $gen_much_sus33 = "hacker" wide ascii
        $gen_much_sus34 = "grayhat" nocase wide ascii
        $gen_much_sus35 = "Microsoft FrontPage" wide ascii
        $gen_much_sus36 = "Rootkit" wide ascii
        $gen_much_sus37 = "rootkit" wide ascii
        $gen_much_sus38 = "/*-/*-*/" wide ascii
        $gen_much_sus39 = "u\"+\"n\"+\"s" wide ascii
        $gen_much_sus40 = "\"e\"+\"v" wide ascii
        $gen_much_sus41 = "a\"+\"l\"" wide ascii
        $gen_much_sus42 = "\"+\"(\"+\"" wide ascii
        $gen_much_sus43 = "q\"+\"u\"" wide ascii
        $gen_much_sus44 = "\"u\"+\"e" wide ascii
        $gen_much_sus45 = "/*//*/" wide ascii
        $gen_much_sus46 = "(\"/*/\"" wide ascii
        $gen_much_sus47 = "eval(eval(" wide ascii
        // self remove
        $gen_much_sus48 = "unlink(__FILE__)" wide ascii
        $gen_much_sus49 = "Shell.Users" wide ascii
        $gen_much_sus50 = "PasswordType=Regular" wide ascii
        $gen_much_sus51 = "-Expire=0" wide ascii
        $gen_much_sus60 = "_=$$_" wide ascii
        $gen_much_sus61 = "_=$$_" wide ascii
        $gen_much_sus62 = "++;$" wide ascii
        $gen_much_sus63 = "++; $" wide ascii
        $gen_much_sus64 = "_.=$_" wide ascii
        $gen_much_sus70 = "-perm -04000" wide ascii
        $gen_much_sus71 = "-perm -02000" wide ascii
        $gen_much_sus72 = "grep -li password" wide ascii
        $gen_much_sus73 = "-name config.inc.php" wide ascii
        // touch without parameters sets the time to now, not malicious and gives fp
        $gen_much_sus75 = "password crack" wide ascii
        $gen_much_sus76 = "mysqlDll.dll" wide ascii
        $gen_much_sus77 = "net user" wide ascii
        $gen_much_sus80 = "fopen(\".htaccess\",\"w" wide ascii
        $gen_much_sus81 = /strrev\(['"]/ wide ascii
        $gen_much_sus82 = "PHPShell" fullword wide ascii
        $gen_much_sus821= "PHP Shell" fullword wide ascii
        $gen_much_sus83 = "phpshell" fullword wide ascii
        $gen_much_sus84 = "PHPshell" fullword wide ascii
        $gen_much_sus87 = "deface" wide ascii
        $gen_much_sus88 = "Deface" wide ascii
        $gen_much_sus89 = "backdoor" wide ascii
        $gen_much_sus90 = "r00t" fullword wide ascii
        $gen_much_sus91 = "xp_cmdshell" fullword wide ascii
        $gen_much_sus92 = "base64_decode(base64_decode(" fullword wide ascii
        $gen_much_sus93 = "eval(\"/*" wide ascii
        $gen_much_sus94 = "http_response_code(404)" wide ascii

        $gif = { 47 49 46 38 }


    condition:
        //any of them or
        not (
            any of ( $gfp* )
        )
        and not (
            any of ( $gfp_tiny* )
        )
        and (
            any of ( $inp* )
        )
        and (
            not any of ( $cfp* ) and
                (
                    any of ( $callback* )  or
                    all of ( $m_callback* )
                )
            )
            and
            ( filesize < 1000 or (
                $gif at 0 or
                (
                    filesize < 4KB and
                    (
                        1 of ( $gen_much_sus* ) or
                        2 of ( $gen_bit_sus* )
                    )
                ) or (
                    filesize < 20KB and
                    (
                        2 of ( $gen_much_sus* ) or
                        3 of ( $gen_bit_sus* )
                    )
                ) or (
                    filesize < 50KB and
                    (
                        2 of ( $gen_much_sus* ) or
                        4 of ( $gen_bit_sus* )
                    )
                ) or (
                    filesize < 100KB and
                    (
                        2 of ( $gen_much_sus* ) or
                        6 of ( $gen_bit_sus* )
                    )
                ) or (
                    filesize < 150KB and
                    (
                        3 of ( $gen_much_sus* ) or
                        7 of ( $gen_bit_sus* )
                    )
                ) or (
                    filesize < 500KB and
                    (
                        4 of ( $gen_much_sus* ) or
                        8 of ( $gen_bit_sus* )
                    )
                )
            )
        )
}

rule WEBSHELL_PHP_Base64_Encoded_Payloads : FILE {
    meta:
        description = "php webshell containing base64 encoded payload"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "88d0d4696c9cb2d37d16e330e236cb37cfaec4cd"
        hash = "e3b4e5ec29628791f836e15500f6fdea19beaf3e8d9981c50714656c50d3b365"
        hash = "e726cd071915534761822805724c6c6bfe0fcac604a86f09437f03f301512dc5"
        hash = "39b8871928d00c7de8d950d25bff4cb19bf9bd35942f7fee6e0f397ff42fbaee"
        hash = "8cc9802769ede56f1139abeaa0735526f781dff3b6c6334795d1d0f19161d076"
        hash = "4cda0c798908b61ae7f4146c6218d7b7de14cbcd7c839edbdeb547b5ae404cd4"
        hash = "afd9c9b0df0b2ca119914ea0008fad94de3bd93c6919f226b793464d4441bdf4"
        hash = "b2048dc30fc7681094a0306a81f4a4cc34f0b35ccce1258c20f4940300397819"
        hash = "da6af9a4a60e3a484764010fbf1a547c2c0a2791e03fc11618b8fc2605dceb04"
        hash = "222cd9b208bd24955bcf4f9976f9c14c1d25e29d361d9dcd603d57f1ea2b0aee"
        hash = "98c1937b9606b1e8e0eebcb116a784c9d2d3db0039b21c45cba399e86c92c2fa"
        hash = "6b6cd1ef7e78e37cbcca94bfb5f49f763ba2f63ed8b33bc4d7f9e5314c87f646"
        hash = "51c2c8b94c4b8cce806735bcf6e5aa3f168f0f7addce47b699b9a4e31dc71b47"
        hash = "7a16311a371f03b29d5220484e7ecbe841cfaead4e73c17aa6a9c23b5d94544d"
        hash = "e2b1dfcfaa61e92526a3a444be6c65330a8db4e692543a421e19711760f6ffe2"

        id = "4e42b47d-725b-5e1f-9408-6c6329f60506"
    strings:
        $decode1 = "base64_decode" fullword nocase wide ascii
        $decode2 = "openssl_decrypt" fullword nocase wide ascii
        // exec
        $one1 = "leGVj"
        $one2 = "V4ZW"
        $one3 = "ZXhlY"
        $one4 = "UAeABlAGMA"
        $one5 = "lAHgAZQBjA"
        $one6 = "ZQB4AGUAYw"
        // shell_exec
        $two1 = "zaGVsbF9leGVj"
        $two2 = "NoZWxsX2V4ZW"
        $two3 = "c2hlbGxfZXhlY"
        $two4 = "MAaABlAGwAbABfAGUAeABlAGMA"
        $two5 = "zAGgAZQBsAGwAXwBlAHgAZQBjA"
        $two6 = "cwBoAGUAbABsAF8AZQB4AGUAYw"
        // passthru
        $three1 = "wYXNzdGhyd"
        $three2 = "Bhc3N0aHJ1"
        $three3 = "cGFzc3Rocn"
        $three4 = "AAYQBzAHMAdABoAHIAdQ"
        $three5 = "wAGEAcwBzAHQAaAByAHUA"
        $three6 = "cABhAHMAcwB0AGgAcgB1A"
        // system
        $four1 = "zeXN0ZW"
        $four2 = "N5c3Rlb"
        $four3 = "c3lzdGVt"
        $four4 = "MAeQBzAHQAZQBtA"
        $four5 = "zAHkAcwB0AGUAbQ"
        $four6 = "cwB5AHMAdABlAG0A"
        // popen
        $five1 = "wb3Blb"
        $five2 = "BvcGVu"
        $five3 = "cG9wZW"
        $five4 = "AAbwBwAGUAbg"
        $five5 = "wAG8AcABlAG4A"
        $five6 = "cABvAHAAZQBuA"
        // proc_open
        $six1 = "wcm9jX29wZW"
        $six2 = "Byb2Nfb3Blb"
        $six3 = "cHJvY19vcGVu"
        $six4 = "AAcgBvAGMAXwBvAHAAZQBuA"
        $six5 = "wAHIAbwBjAF8AbwBwAGUAbg"
        $six6 = "cAByAG8AYwBfAG8AcABlAG4A"
        // pcntl_exec
        $seven1 = "wY250bF9leGVj"
        $seven2 = "BjbnRsX2V4ZW"
        $seven3 = "cGNudGxfZXhlY"
        $seven4 = "AAYwBuAHQAbABfAGUAeABlAGMA"
        $seven5 = "wAGMAbgB0AGwAXwBlAHgAZQBjA"
        $seven6 = "cABjAG4AdABsAF8AZQB4AGUAYw"
        // eval
        $eight1 = "ldmFs"
        $eight2 = "V2YW"
        $eight3 = "ZXZhb"
        $eight4 = "UAdgBhAGwA"
        $eight5 = "lAHYAYQBsA"
        $eight6 = "ZQB2AGEAbA"
        // assert
        $nine1 = "hc3Nlcn"
        $nine2 = "Fzc2Vyd"
        $nine3 = "YXNzZXJ0"
        $nine4 = "EAcwBzAGUAcgB0A"
        $nine5 = "hAHMAcwBlAHIAdA"
        $nine6 = "YQBzAHMAZQByAHQA"

        // false positives

        // execu
        $execu1 = "leGVjd"
        $execu2 = "V4ZWN1"
        $execu3 = "ZXhlY3"

        // esystem like e.g. filesystem
        $esystem1 = "lc3lzdGVt"
        $esystem2 = "VzeXN0ZW"
        $esystem3 = "ZXN5c3Rlb"

        // opening
        $opening1 = "vcGVuaW5n"
        $opening2 = "9wZW5pbm"
        $opening3 = "b3BlbmluZ"

        // false positives
        $fp1 = { D0 CF 11 E0 A1 B1 1A E1 }
        // api.telegram
        $fp2 = "YXBpLnRlbGVncmFtLm9"
        // Log files
        $fp3 = " GET /"
        $fp4 = " POST /"

    $fpa1 = "/cn=Recipients"

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 300KB and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and not any of ( $fp* ) and any of ( $decode* ) and
        ( ( any of ( $one* ) and not any of ( $execu* ) ) or any of ( $two* ) or any of ( $three* ) or
        ( any of ( $four* ) and not any of ( $esystem* ) ) or
        ( any of ( $five* ) and not any of ( $opening* ) ) or any of ( $six* ) or any of ( $seven* ) or any of ( $eight* ) or any of ( $nine* ) )
}

rule WEBSHELL_PHP_Unknown_1 {
    meta:
        description = "obfuscated php webshell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        hash = "12ce6c7167b33cc4e8bdec29fb1cfc44ac9487d1"
        hash = "cf4abbd568ce0c0dfce1f2e4af669ad2"
        date = "2021/01/07"
        modified = "2023-04-05"

        id = "93d01a4c-4c18-55d2-b682-68a1f6460889"
    strings:
        $sp0 = /^<\?php \$[a-z]{3,30} = '/ wide ascii
        $sp1 = "=explode(chr(" wide ascii
        $sp2 = "; if (!function_exists('" wide ascii
        $sp3 = " = NULL; for(" wide ascii

    condition:
        filesize <300KB and all of ($sp*)
}

rule WEBSHELL_PHP_Generic_Eval {
    meta:
        description = "Generic PHP webshell which uses any eval/exec function in the same line with user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "a61437a427062756e2221bfb6d58cd62439d09d9"
        hash = "90c5cc724ec9cf838e4229e5e08955eec4d7bf95"
        hash = "2b41abc43c5b6c791d4031005bf7c5104a98e98a00ee24620ce3e8e09a78e78f"
        hash = "5c68a0fa132216213b66a114375b07b08dc0cb729ddcf0a29bff9ca7a22eaaf4"
        hash = "de3c01f55d5346577922bbf449faaaaa1c8d1aaa64c01e8a1ee8c9d99a41a1be"
        hash = "124065176d262bde397b1911648cea16a8ff6a4c8ab072168d12bf0662590543"
        hash = "cd7450f3e5103e68741fd086df221982454fbcb067e93b9cbd8572aead8f319b"
        hash = "ab835ce740890473adf5cc804055973b926633e39c59c2bd98da526b63e9c521"
        hash = "31ff9920d401d4fbd5656a4f06c52f1f54258bc42332fc9456265dca7bb4c1ea"
        hash = "64e6c08aa0b542481b86a91cdf1f50c9e88104a8a4572a8c6bd312a9daeba60e"
        hash = "80e98e8a3461d7ba15d869b0641cdd21dd5b957a2006c3caeaf6f70a749ca4bb"
        hash = "93982b8df76080e7ba4520ae4b4db7f3c867f005b3c2f84cb9dff0386e361c35"
        hash = "51c2c8b94c4b8cce806735bcf6e5aa3f168f0f7addce47b699b9a4e31dc71b47"
        hash = "7a16311a371f03b29d5220484e7ecbe841cfaead4e73c17aa6a9c23b5d94544d"
        hash = "7ca5dec0515dd6f401cb5a52c313f41f5437fc43eb62ea4bcc415a14212d09e9"
        hash = "fd5f0f81204ca6ca6e93343500400d5853012e88254874fc9f62efe0fde7ab3c"
        hash = "883f48ed4e9646da078cabf6b8b4946d9f199660262502650f76450ecf60ddd5"
        hash = "6d042b6393669bb4d98213091cabe554ab192a6c916e86c04d06cc2a4ca92c00"
        hash = "dd5d8a9b4bb406e0b8f868165a1714fe54ffb18e621582210f96f6e5ae850b33"


        id = "79cfbd88-f6f7-5cba-a325-0a99962139ca"
    strings:
        // new: eval($GLOBALS['_POST'
        $geval = /\b(exec|shell_exec|passthru|system|popen|proc_open|pcntl_exec|eval|assert)[\t ]{0,300}(\(base64_decode)?(\(stripslashes)?[\t ]{0,300}(\(trim)?[\t ]{0,300}\(\$(_POST|_GET|_REQUEST|_SERVER\s?\[['"]HTTP_|GLOBALS\[['"]_(POST|GET|REQUEST))/ wide ascii

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"
        // Log files
        $gfp_3 = " GET /"
        $gfp_4 = " POST /"
    condition:
        filesize < 300KB and not (
            any of ( $gfp* )
        )
        and $geval
}

rule WEBSHELL_PHP_Double_Eval_Tiny {
    meta:
        description = "PHP webshell which probably hides the input inside an eval()ed obfuscated string"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 70
        date = "2021-01-11"
        modified = "2026-02-23"
        hash = "f66fb918751acc7b88a17272a044b5242797976c73a6e54ac6b04b02f61e9761"
        hash = "6b2f0a3bd80019dea536ddbf92df36ab897dd295840cb15bb7b159d0ee2106ff"
        hash = "aabfd179aaf716929c8b820eefa3c1f613f8dcac"
        hash = "9780c70bd1c76425d4313ca7a9b89dda77d2c664"
        hash = "006620d2a701de73d995fc950691665c0692af11"


        id = "868db363-83d3-57e2-ac8d-c6125e9bdd64"
    strings:
        $payload = /(\beval[\t ]{0,500}\([^)]|\bassert[\t ]{0,500}\([^)])/ nocase wide ascii
        $fp1 = "clone" fullword wide ascii
        $fp2 = "* @assert" ascii
        $fp3 = "*@assert" ascii
        $fp4 = "--EXPECT--" ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize > 70 and filesize < 300 and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and #payload >= 2 and not any of ( $fp* )
}

rule WEBSHELL_PHP_OBFUSC {
    meta:
        description = "PHP webshell obfuscated"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/12"
        modified = "2025-09-22"
        hash = "eec9ac58a1e763f5ea0f7fa249f1fe752047fa60"
        hash = "181a71c99a4ae13ebd5c94bfc41f9ec534acf61cd33ef5bce5fb2a6f48b65bf4"
        hash = "76d4e67e13c21662c4b30aab701ce9cdecc8698696979e504c288f20de92aee7"
        hash = "1d0643927f04cb1133f00aa6c5fa84aaf88e5cf14d7df8291615b402e8ab6dc2"
        id = "f66e337b-8478-5cd3-b01a-81133edaa8e5"
    strings:

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"
        $gfp13 = "assert(\\\""
        $gfp14 = "PhutilUTF8TestCase"
        $gfp15 = "chr(195).chr(128) => 'A',"  // 3d413ceb54e929d6af2e64ebb8df7ba2452a7aac876dddcf6336c3445e7bcc91, wordpress formatter.php

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_obfuscation_multi
        $o1 = "chr(" nocase wide ascii
        $o2 = "chr (" nocase wide ascii
        // not excactly a string function but also often used in obfuscation
        $o3 = "goto" fullword nocase wide ascii
        $o4 = "\\x9" wide ascii
        $o5 = "\\x3" wide ascii
        // just picking some random numbers because they should appear often enough in a long obfuscated blob and it's faster than a regex
        $o6 = "\\61" wide ascii
        $o7 = "\\44" wide ascii
        $o8 = "\\112" wide ascii
        $o9 = "\\120" wide ascii
        $fp1 = "$goto" wide ascii

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload2 = /\bexec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload3 = /\bshell_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload4 = /\bpassthru[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload5 = /\bsystem[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload6 = /\bpopen[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload7 = /\bproc_open[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload9 = /\bassert[\n\t ]{0,500}\([^)0]/ nocase wide ascii
        $cpayload10 = /\bpreg_replace[\n\t ]{0,500}\([^\)]{1,100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload20 = /\bcreate_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]{0,500}[,}\)]/ nocase wide ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]{0,500}(\([^\)]|\/\*)/ nocase wide ascii
        $m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
        // TODO backticks

    condition:
        not (
            any of ( $gfp* )
        )
        and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and (
            // allow different amounts of potential obfuscation functions depending on filesize
            not $fp1 and (
                (
                        filesize < 20KB and
                        (
                            ( #o1+#o2 ) > 50 or
                            #o3 > 10 or
                            ( #o4+#o5+#o6+#o7+#o8+#o9 ) > 20
                        )
                ) or (
                        filesize < 200KB and
                        (
                            ( #o1+#o2 ) > 200 or
                            #o3 > 30 or
                            ( #o4+#o5+#o6+#o7+#o8+#o9 ) > 30
                        )

                )
            )


        )
        and (
            any of ( $cpayload* ) or
        all of ( $m_cpayload_preg_filter* )
        )

}

rule WEBSHELL_PHP_OBFUSC_Encoded {
    meta:
        description = "PHP webshell obfuscated by encoding"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/04/18"
        modified = "2023-04-05"
        score = 70
        hash = "119fc058c9c5285498a47aa271ac9a27f6ada1bf4d854ccd4b01db993d61fc52"
        hash = "d5ca3e4505ea122019ea263d6433221030b3f64460d3ce2c7d0d63ed91162175"
        hash = "8a1e2d72c82f6a846ec066d249bfa0aaf392c65149d39b7b15ba19f9adc3b339"


        id = "134c1189-1b41-58d5-af66-beaa4795a704"
    strings:
        // one without plain e, one without plain v, to avoid hitting on plain "eval("
        $enc_eval1 = /(e|\\x65|\\101)(\\x76|\\118)(a|\\x61|\\97)(l|\\x6c|\\108)(\(|\\x28|\\40)/ wide ascii nocase
        $enc_eval2 = /(\\x65|\\101)(v|\\x76|\\118)(a|\\x61|\\97)(l|\\x6c|\\108)(\(|\\x28|\\40)/ wide ascii nocase
        // one without plain a, one without plain s, to avoid hitting on plain "assert("
        $enc_assert1 = /(a|\\97|\\x61)(\\115|\\x73)(s|\\115|\\x73)(e|\\101|\\x65)(r|\\114|\\x72)(t|\\116|\\x74)(\(|\\x28|\\40)/ wide ascii nocase
        $enc_assert2 = /(\\97|\\x61)(s|\\115|\\x73)(s|\\115|\\x73)(e|\\101|\\x65)(r|\\114|\\x72)(t|\\116|\\x74)(\(|\\x28|\\40)/ wide ascii nocase

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 700KB and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and any of ( $enc* )
}

rule WEBSHELL_PHP_OBFUSC_Encoded_Mixed_Dec_And_Hex {
    meta:
        description = "PHP webshell obfuscated by encoding of mixed hex and dec"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/04/18"
        modified = "2023-04-05"
        hash = "0e21931b16f30b1db90a27eafabccc91abd757fa63594ba8a6ad3f477de1ab1c"
        hash = "929975272f0f42bf76469ed89ebf37efcbd91c6f8dac1129c7ab061e2564dd06"
        hash = "88fce6c1b589d600b4295528d3fcac161b581f739095b99cd6c768b7e16e89ff"
        hash = "883f48ed4e9646da078cabf6b8b4946d9f199660262502650f76450ecf60ddd5"
        hash = "50389c3b95a9de00220fc554258fda1fef01c62dad849e66c8a92fc749523457"
        hash = "c4ab4319a77b751a45391aa01cde2d765b095b0e3f6a92b0b8626d5c7e3ad603"
        hash = "df381f04fca2522e2ecba0f5de3f73a655d1540e1cf865970f5fa3bf52d2b297"
        hash = "401388d8b97649672d101bf55694dd175375214386253d0b4b8d8d801a89549c"
        hash = "99fc39a12856cc1a42bb7f90ffc9fe0a5339838b54a63e8f00aa98961c900618"
        hash = "fb031af7aa459ee88a9ca44013a76f6278ad5846aa20e5add4aeb5fab058d0ee"
        hash = "dd5d8a9b4bb406e0b8f868165a1714fe54ffb18e621582210f96f6e5ae850b33"
        hash = "0ff05e6695074f98b0dee6200697a997c509a652f746d2c1c92c0b0a0552ca47"

        id = "9ae920e2-17c8-58fd-8566-90d461a54943"
    strings:
        // "e\x4a\x48\x5a\x70\x63\62\154\x30\131\171\101\x39\111\x43\x52\x66\x51\
        //$mix = /['"]\\x?[0-9a-f]{2,3}[\\\w]{2,20}\\\d{1,3}[\\\w]{2,20}\\x[0-9a-f]{2}\\/ wide ascii nocase
        $mix = /['"](\w|\\x?[0-9a-f]{2,3})[\\x0-9a-f]{2,20}\\\d{1,3}[\\x0-9a-f]{2,20}\\x[0-9a-f]{2}\\/ wide ascii nocase

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 700KB and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and any of ( $mix* )
}

rule WEBSHELL_PHP_OBFUSC_Tiny {
    meta:
        description = "PHP webshell obfuscated"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/12"
        modified = "2024-03-11"
        hash = "b7b7aabd518a2f8578d4b1bc9a3af60d155972f1"
        hash = "694ec6e1c4f34632a9bd7065f73be473"
        hash = "5c871183444dbb5c8766df6b126bd80c624a63a16cc39e20a0f7b002216b2ba5"

        id = "d78e495f-54d2-5f5f-920f-fb6612afbca3"
    strings:
        // 'ev'.'al'
        $obf1 = /\w'\.'\w/ wide ascii
        $obf2 = /\w\"\.\"\w/ wide ascii
        $obf3 = "].$" wide ascii

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload2 = /\bexec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload3 = /\bshell_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload4 = /\bpassthru[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload5 = /\bsystem[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload6 = /\bpopen[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload7 = /\bproc_open[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload9 = /\bassert[\n\t ]{0,500}\([^)0]/ nocase wide ascii
        $cpayload10 = /\bpreg_replace[\n\t ]{0,500}\([^\)]{1,100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload20 = /\bcreate_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]{0,500}[,}\)]/ nocase wide ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]{0,500}(\([^\)]|\/\*)/ nocase wide ascii
        $m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
        // TODO backticks

    condition:
        //any of them or
        filesize < 500 and not (
            any of ( $gfp* )
        )
        and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and (
            any of ( $cpayload* ) or
        all of ( $m_cpayload_preg_filter* )
        )
        and
        ( ( #obf1 + #obf2 ) > 2 or #obf3 > 10 )
}

rule WEBSHELL_PHP_OBFUSC_Str_Replace {
    meta:
        description = "PHP webshell which eval()s obfuscated string"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/12"
        modified = "2023-04-05"
        hash = "691305753e26884d0f930cda0fe5231c6437de94"
        hash = "7efd463aeb5bf0120dc5f963b62463211bd9e678"
        hash = "fb655ddb90892e522ae1aaaf6cd8bde27a7f49ef"
        hash = "d1863aeca1a479462648d975773f795bb33a7af2"
        hash = "4d31d94b88e2bbd255cf501e178944425d40ee97"
        hash = "e1a2af3477d62a58f9e6431f5a4a123fb897ea80"

        id = "1f5b93c9-bdeb-52c7-a99a-69869634a574"
    strings:
        $payload1 = "str_replace" fullword wide ascii
        $payload2 = "function" fullword wide ascii
        $goto = "goto" fullword wide ascii
        //$hex  = "\\x"
        $chr1  = "\\61" wide ascii
        $chr2  = "\\112" wide ascii
        $chr3  = "\\120" wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 300KB and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and any of ( $payload* ) and #goto > 1 and
        ( #chr1 > 10 or #chr2 > 10 or #chr3 > 10 )
}

rule WEBSHELL_PHP_OBFUSC_Fopo {
    meta:
        description = "PHP webshell which eval()s obfuscated string"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        hash = "fbcff8ea5ce04fc91c05384e847f2c316e013207"
        hash = "6da57ad8be1c587bb5cc8a1413f07d10fb314b72"
        hash = "a698441f817a9a72908a0d93a34133469f33a7b34972af3e351bdccae0737d99"
        date = "2021/01/12"
        modified = "2023-04-05"

        id = "a298e99d-1ba8-58c8-afb9-fc988ea91e9a"
    strings:
        $payload = /(\beval[\t ]{0,500}\([^)]|\bassert[\t ]{0,500}\([^)])/ nocase wide ascii
        // ;@eval(
        $one1 = "7QGV2YWwo" wide ascii
        $one2 = "tAZXZhbC" wide ascii
        $one3 = "O0BldmFsK" wide ascii
        $one4 = "sAQABlAHYAYQBsACgA" wide ascii
        $one5 = "7AEAAZQB2AGEAbAAoA" wide ascii
        $one6 = "OwBAAGUAdgBhAGwAKA" wide ascii
        // ;@assert(
        $two1 = "7QGFzc2VydC" wide ascii
        $two2 = "tAYXNzZXJ0K" wide ascii
        $two3 = "O0Bhc3NlcnQo" wide ascii
        $two4 = "sAQABhAHMAcwBlAHIAdAAoA" wide ascii
        $two5 = "7AEAAYQBzAHMAZQByAHQAKA" wide ascii
        $two6 = "OwBAAGEAcwBzAGUAcgB0ACgA" wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 3000KB and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and $payload and
        ( any of ( $one* ) or any of ( $two* ) )
}

rule WEBSHELL_PHP_Gzinflated {
    meta:
        description = "PHP webshell which directly eval()s obfuscated string"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/12"
        modified = "2023-07-05"
        hash = "49e5bc75a1ec36beeff4fbaeb16b322b08cf192d"
        hash = "6f36d201cd32296bad9d5864c7357e8634f365cc"
        hash = "ab10a1e69f3dfe7c2ad12b2e6c0e66db819c2301"
        hash = "a6cf337fe11fe646d7eee3d3f09c7cb9643d921d"
        hash = "07eb6634f28549ebf26583e8b154c6a579b8a733"

        id = "9cf99ae4-9f7c-502f-9294-b531002953d6"
    strings:
        $payload2 = /eval\s?\(\s?("\?>".)?gzinflate\s?\(\s?base64_decode\s?\(/ wide ascii nocase
        $payload4 = /eval\s?\(\s?("\?>".)?gzuncompress\s?\(\s?(base64_decode|gzuncompress)/ wide ascii nocase
        $payload6 = /eval\s?\(\s?("\?>".)?gzdecode\s?\(\s?base64_decode\s?\(/ wide ascii nocase
        $payload7 = /eval\s?\(\s?base64_decode\s?\(/ wide ascii nocase
        $payload8 = /eval\s?\(\s?pack\s?\(/ wide ascii nocase

        // api.telegram
        $fp1 = "YXBpLnRlbGVncmFtLm9"

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 700KB and not (
            any of ( $gfp* )
        )
        and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and 1 of ( $payload* ) and not any of ( $fp* )
}

rule WEBSHELL_PHP_OBFUSC_3 {
    meta:
        description = "PHP webshell which eval()s obfuscated string"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 70
        date = "2021/04/17"
        modified = "2024-12-09"
        hash = "11bb1fa3478ec16c00da2a1531906c05e9c982ea"
        hash = "d6b851cae249ea6744078393f622ace15f9880bc"
        hash = "14e02b61905cf373ba9234a13958310652a91ece"
        hash = "6f97f607a3db798128288e32de851c6f56e91c1d"

        id = "f2017e6f-0623-53ff-aa26-a479f3a02024"
    strings:
        $obf1 = "chr(" wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_callback
        // the end is 1. ( followed by anything but a direct closing ) 2. /* for the start of an obfuscation comment
        $callback1 = /\bob_start[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback2 = /\barray_diff_uassoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback3 = /\barray_diff_ukey[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback4 = /\barray_filter[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback5 = /\barray_intersect_uassoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback6 = /\barray_intersect_ukey[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback7 = /\barray_map[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback8 = /\barray_reduce[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback9 = /\barray_udiff_assoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback10 = /\barray_udiff_uassoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback11 = /\barray_udiff[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback12 = /\barray_uintersect_assoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback13 = /\barray_uintersect_uassoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback14 = /\barray_uintersect[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback15 = /\barray_walk_recursive[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback16 = /\barray_walk[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback17 = /\bassert_options[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback18 = /\buasort[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback19 = /\buksort[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback20 = /\busort[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback21 = /\bpreg_replace_callback[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback22 = /\bspl_autoload_register[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback23 = /\biterator_apply[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback24 = /\bcall_user_func[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback25 = /\bcall_user_func_array[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback26 = /\bregister_shutdown_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback27 = /\bregister_tick_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback28 = /\bset_error_handler[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback29 = /\bset_exception_handler[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback30 = /\bsession_set_save_handler[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback31 = /\bsqlite_create_aggregate[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback32 = /\bsqlite_create_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback33 = /\bmb_ereg_replace_callback[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii

        $m_callback1 = /\bfilter_var[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $m_callback2 = "FILTER_CALLBACK" fullword wide ascii

        $cfp1 = /ob_start\(['\"]ob_gzhandler/ nocase wide ascii
        $cfp2 = "IWPML_Backend_Action_Loader" ascii wide
        $cfp3 = "<?phpclass WPML" ascii
        $cfp4 = "      return implode('', "

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload2 = /\bexec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload3 = /\bshell_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload4 = /\bpassthru[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload5 = /\bsystem[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload6 = /\bpopen[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload7 = /\bproc_open[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload9 = /\bassert[\n\t ]{0,500}\([^)0]/ nocase wide ascii
        $cpayload10 = /\bpreg_replace[\n\t ]{0,500}\([^\)]{1,100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload20 = /\bcreate_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]{0,500}[,}\)]/ nocase wide ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]{0,500}(\([^\)]|\/\*)/ nocase wide ascii
        $m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
        // TODO backticks

        //strings from private rule capa_php_obfuscation_single
        $cobfs1 = "gzinflate" fullword nocase wide ascii
        $cobfs2 = "gzuncompress" fullword nocase wide ascii
        $cobfs3 = "gzdecode" fullword nocase wide ascii
        $cobfs4 = "base64_decode" fullword nocase wide ascii
        $cobfs5 = "pack" fullword nocase wide ascii
        $cobfs6 = "undecode" fullword nocase wide ascii

        //strings from private rule capa_gen_sus

        // these strings are just a bit suspicious, so several of them are needed, depending on filesize
        $gen_bit_sus1  = /:\s{0,20}eval}/ nocase wide ascii
        $gen_bit_sus2  = /\.replace\(\/\w\/g/ nocase wide ascii
        $gen_bit_sus6  = "self.delete"
        $gen_bit_sus9  = "\"cmd /c" nocase
        $gen_bit_sus10 = "\"cmd\"" nocase
        $gen_bit_sus11 = "\"cmd.exe" nocase
        $gen_bit_sus12 = "%comspec%" wide ascii
        $gen_bit_sus13 = "%COMSPEC%" wide ascii
        //TODO:$gen_bit_sus12 = ".UserName" nocase
        $gen_bit_sus18 = "Hklm.GetValueNames();" nocase
        // bonus string for proxylogon exploiting webshells
        $gen_bit_sus19 = "http://schemas.microsoft.com/exchange/" wide ascii
        $gen_bit_sus21 = "\"upload\"" wide ascii
        $gen_bit_sus22 = "\"Upload\"" wide ascii
        $gen_bit_sus23 = "UPLOAD" fullword wide ascii
        $gen_bit_sus24 = "fileupload" wide ascii
        $gen_bit_sus25 = "file_upload" wide ascii
        // own base64 or base32 func
        $gen_bit_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword wide ascii
        $gen_bit_sus29b = "abcdefghijklmnopqrstuvwxyz234567" fullword wide ascii
        $gen_bit_sus30 = "serv-u" wide ascii
        $gen_bit_sus31 = "Serv-u" wide ascii
        $gen_bit_sus32 = "Army" fullword wide ascii
        // single letter paramweter
        $gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword wide ascii
        $gen_bit_sus34 = "Content-Transfer-Encoding: Binary" wide ascii
        $gen_bit_sus35 = "crack" fullword wide ascii

        $gen_bit_sus44 = "<pre>" wide ascii
        $gen_bit_sus45 = "<PRE>" wide ascii
        $gen_bit_sus46 = "shell_" wide ascii
        //fp: $gen_bit_sus47 = "Shell" fullword wide ascii
        $gen_bit_sus50 = "bypass" wide ascii
        $gen_bit_sus52 = " ^ $" wide ascii
        $gen_bit_sus53 = ".ssh/authorized_keys" wide ascii
        $gen_bit_sus55 = /\w'\.'\w/ wide ascii
        $gen_bit_sus56 = /\w\"\.\"\w/ wide ascii
        $gen_bit_sus57 = "dumper" wide ascii
        $gen_bit_sus59 = "'cmd'" wide ascii
        $gen_bit_sus60 = "\"execute\"" wide ascii
        $gen_bit_sus61 = "/bin/sh" wide ascii
        $gen_bit_sus62 = "Cyber" wide ascii
        $gen_bit_sus63 = "portscan" fullword wide ascii
        //$gen_bit_sus64 = "\"command\"" fullword wide ascii
        //$gen_bit_sus65 = "'command'" fullword wide ascii
        $gen_bit_sus66 = "whoami" fullword wide ascii
        $gen_bit_sus67 = "$password='" fullword wide ascii
        $gen_bit_sus68 = "$password=\"" fullword wide ascii
        $gen_bit_sus69 = "$cmd" fullword wide ascii
        $gen_bit_sus70 = "\"?>\"." fullword wide ascii
        $gen_bit_sus71 = "Hacking" fullword wide ascii
        $gen_bit_sus72 = "hacking" fullword wide ascii
        $gen_bit_sus73 = ".htpasswd" wide ascii
        $gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/ wide ascii

        // very suspicious strings, one is enough
        $gen_much_sus7  = "Web Shell" nocase
        $gen_much_sus8  = "WebShell" nocase
        $gen_much_sus3  = "hidded shell"
        $gen_much_sus4  = "WScript.Shell.1" nocase
        $gen_much_sus5  = "AspExec"
        $gen_much_sus14 = "\\pcAnywhere\\" nocase
        $gen_much_sus15 = "antivirus" nocase
        $gen_much_sus16 = "McAfee" nocase
        $gen_much_sus17 = "nishang"
        $gen_much_sus18 = "\"unsafe" fullword wide ascii
        $gen_much_sus19 = "'unsafe" fullword wide ascii
        $gen_much_sus24 = "exploit" fullword wide ascii
        $gen_much_sus25 = "Exploit" fullword wide ascii
        $gen_much_sus26 = "TVqQAAMAAA" wide ascii
        $gen_much_sus30 = "Hacker" wide ascii
        $gen_much_sus31 = "HACKED" fullword wide ascii
        $gen_much_sus32 = "hacked" fullword wide ascii
        $gen_much_sus33 = "hacker" wide ascii
        $gen_much_sus34 = "grayhat" nocase wide ascii
        $gen_much_sus35 = "Microsoft FrontPage" wide ascii
        $gen_much_sus36 = "Rootkit" wide ascii
        $gen_much_sus37 = "rootkit" wide ascii
        $gen_much_sus38 = "/*-/*-*/" wide ascii
        $gen_much_sus39 = "u\"+\"n\"+\"s" wide ascii
        $gen_much_sus40 = "\"e\"+\"v" wide ascii
        $gen_much_sus41 = "a\"+\"l\"" wide ascii
        $gen_much_sus42 = "\"+\"(\"+\"" wide ascii
        $gen_much_sus43 = "q\"+\"u\"" wide ascii
        $gen_much_sus44 = "\"u\"+\"e" wide ascii
        $gen_much_sus45 = "/*//*/" wide ascii
        $gen_much_sus46 = "(\"/*/\"" wide ascii
        $gen_much_sus47 = "eval(eval(" wide ascii
        // self remove
        $gen_much_sus48 = "unlink(__FILE__)" wide ascii
        $gen_much_sus49 = "Shell.Users" wide ascii
        $gen_much_sus50 = "PasswordType=Regular" wide ascii
        $gen_much_sus51 = "-Expire=0" wide ascii
        $gen_much_sus60 = "_=$$_" wide ascii
        $gen_much_sus61 = "_=$$_" wide ascii
        $gen_much_sus62 = "++;$" wide ascii
        $gen_much_sus63 = "++; $" wide ascii
        $gen_much_sus64 = "_.=$_" wide ascii
        $gen_much_sus70 = "-perm -04000" wide ascii
        $gen_much_sus71 = "-perm -02000" wide ascii
        $gen_much_sus72 = "grep -li password" wide ascii
        $gen_much_sus73 = "-name config.inc.php" wide ascii
        // touch without parameters sets the time to now, not malicious and gives fp
        $gen_much_sus75 = "password crack" wide ascii
        $gen_much_sus76 = "mysqlDll.dll" wide ascii
        $gen_much_sus77 = "net user" wide ascii
        $gen_much_sus80 = "fopen(\".htaccess\",\"w" wide ascii
        $gen_much_sus81 = /strrev\(['"]/ wide ascii
        $gen_much_sus82 = "PHPShell" fullword wide ascii
        $gen_much_sus821= "PHP Shell" fullword wide ascii
        $gen_much_sus83 = "phpshell" fullword wide ascii
        $gen_much_sus84 = "PHPshell" fullword wide ascii
        $gen_much_sus87 = "deface" wide ascii
        $gen_much_sus88 = "Deface" wide ascii
        $gen_much_sus89 = "backdoor" wide ascii
        $gen_much_sus90 = "r00t" fullword wide ascii
        $gen_much_sus91 = "xp_cmdshell" fullword wide ascii
        $gen_much_sus92 = "base64_decode(base64_decode(" fullword wide ascii
        $gen_much_sus93 = "eval(\"/*" wide ascii
        $gen_much_sus94 = "=$_COOKIE;" wide ascii

        $gif = { 47 49 46 38 }


    condition:
        //any of them or
        (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and
        ( (
            not any of ( $cfp* ) and
        (
            any of ( $callback* )  or
            all of ( $m_callback* )
        )
        )
        or (
            any of ( $cpayload* ) or
        all of ( $m_cpayload_preg_filter* )
        )
        ) and (
            any of ( $cobfs* )
        )
        and
        ( filesize < 1KB or
        ( filesize < 3KB and
        ( (
        $gif at 0 or
        (
            filesize < 4KB and
            (
                1 of ( $gen_much_sus* ) or
                2 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 20KB and
            (
                2 of ( $gen_much_sus* ) or
                3 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 50KB and
            (
                2 of ( $gen_much_sus* ) or
                4 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 100KB and
            (
                2 of ( $gen_much_sus* ) or
                6 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 150KB and
            (
                3 of ( $gen_much_sus* ) or
                7 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 500KB and
            (
                4 of ( $gen_much_sus* ) or
                8 of ( $gen_bit_sus* )
            )
        )
        )
        or #obf1 > 10 ) ) )
}

rule WEBSHELL_PHP_Includer_Eval {
    meta:
        description = "PHP webshell which eval()s another included file"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/13"
        modified = "2023-04-05"
        hash = "3a07e9188028efa32872ba5b6e5363920a6b2489"
        hash = "ab771bb715710892b9513b1d075b4e2c0931afb6"
        hash = "202dbcdc2896873631e1a0448098c820c82bcc8385a9f7579a0dc9702d76f580"
        hash = "b51a6d208ec3a44a67cce16dcc1e93cdb06fe150acf16222815333ddf52d4db8"

        id = "995fcc34-f91e-5c9c-97b1-84eed1714d40"
    strings:
        $payload1 = "eval" fullword wide ascii
        $payload2 = "assert" fullword wide ascii
        $include1 = "$_FILE" wide ascii
        $include2 = "include" wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 200 and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and 1 of ( $payload* ) and 1 of ( $include* )
}

rule WEBSHELL_PHP_Includer_Tiny {
    meta:
        description = "Suspicious: Might be PHP webshell includer, check the included file"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/04/17"
        modified = "2023-07-05"
        hash = "0687585025f99596508783b891e26d6989eec2ba"
        hash = "9e856f5cb7cb901b5003e57c528a6298341d04dc"
        hash = "b3b0274cda28292813096a5a7a3f5f77378b8905205bda7bb7e1a679a7845004"

        id = "9bf96ddc-d984-57eb-9803-0b01890711b5"
    strings:
        $php_include1 = /include\(\$_(GET|POST|REQUEST)\[/ nocase wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 100 and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and any of ( $php_include* )
}

rule WEBSHELL_PHP_Dynamic {
    meta:
        description = "PHP webshell using function name from variable, e.g. $a='ev'.'al'; $a($code)"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/01/13"
        modified = "2024-12-09"
        score = 60
        hash = "65dca1e652d09514e9c9b2e0004629d03ab3c3ef"
        hash = "b8ab38dc75cec26ce3d3a91cb2951d7cdd004838"
        hash = "c4765e81550b476976604d01c20e3dbd415366df"
        hash = "2e11ba2d06ebe0aa818e38e24a8a83eebbaae8877c10b704af01bf2977701e73"

        id = "58ad94bc-93c8-509c-9d3a-c9a26538d60c"
    strings:
        $pd_fp1 = "whoops_add_stack_frame" wide ascii
        $pd_fp2 = "new $ec($code, $mode, $options, $userinfo);" wide ascii
        $pd_fp3 = "($i)] = 600;" ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_dynamic
        // php variable regex from https://www.php.net/manual/en/language.variables.basics.php
        $dynamic1 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(\$/ wide ascii
        $dynamic2 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\("/ wide ascii
        $dynamic3 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\('/ wide ascii
        $dynamic4 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(str/ wide ascii
        $dynamic5 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(\)/ wide ascii
        $dynamic6 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(@/ wide ascii
        $dynamic7 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(base64_decode/ wide ascii
        // ${'_'.$_}["_"](${'_'.$_}["__"]
        $dynamic8 = /\$\{[^}]{1,20}}(\[[^\]]{1,20}\])?\(\$\{/ wide ascii

        $fp1 = { 3C 3F 70 68 70 0A 0A 24 61 28 24 62 20 3D 20 33 2C 20 24 63 29 3B } /* <?php\x0a\x0a$a($b = 3, $c); */
        $fp2 = { 3C 3F 70 68 70 0A 0A 24 61 28 24 62 20 3D 20 33 2C 20 2E 2E 2E 20 24 63 29 3B } /* <?php\x0a\x0a$a($b = 3, ... $c); */
        $fp3 = { 3C 3F 70 68 70 0A 0A 24 61 20 3D 20 6E 65 77 20 73 74 61 74 69 63 3A 3A 24 62 28 29 3B} /* <?php\x0a\x0a$a = new static::$b(); */
        $fp4 = { 3C 3F 70 68 70 0A 0A 24 61 20 3D 20 6E 65 77 20 73 65 6C 66 3A 3A 24 62 28 29 3B } /* <?php\x0a\x0a$a = new self::$b(); */
        $fp5 = { 3C 3F 70 68 70 0A 0A 24 61 20 3D 20 5C 22 7B 24 76 61 72 43 61 6C 6C 61 62 6C 65 28 29 7D 5C 22 3B } /* <?php\x0a\x0a$a = \"{$varCallable()}\"; */
        $fp6 = "// TODO error about missing expression" /* <?php\x0a// TODO error about missing expression\x0a$a($b = 3, $c,); */
        $fp7 = "// This is an invalid location for an attribute, "
        $fp8 = "/* Auto-generated from php/php-langspec tests */"
        $fp_dynamic1 = /"\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(\$/ wide ascii // e.g. echo "$callback($text)";
    condition:
        filesize > 20 and filesize < 200 and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and (
            any of ( $dynamic* )
        )
        and not any of ( $pd_fp* )
        and not 1 of ($fp*)
}

rule WEBSHELL_PHP_Dynamic_Big {
    meta:
        description = "PHP webshell using $a($code) for kind of eval with encoded blob to decode, e.g. b374k"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/02/07"
        modified = "2025-08-18"
        score = 50
        hash = "6559bfc4be43a55c6bb2bd867b4c9b929713d3f7f6de8111a3c330f87a9b302c"
        hash = "9e82c9c2fa64e26fd55aa18f74759454d89f968068d46b255bd4f41eb556112e"
        hash = "6def5296f95e191a9c7f64f7d8ac5c529d4a4347ae484775965442162345dc93"
        hash = "dadfdc4041caa37166db80838e572d091bb153815a306c8be0d66c9851b98c10"
        hash = "0a4a292f6e08479c04e5c4fdc3857eee72efa5cd39db52e4a6e405bf039928bd"
        hash = "4326d10059e97809fb1903eb96fd9152cc72c376913771f59fa674a3f110679e"
        hash = "b49d0f942a38a33d2b655b1c32ac44f19ed844c2479bad6e540f69b807dd3022"
        hash = "575edeb905b434a3b35732654eedd3afae81e7d99ca35848c509177aa9bf9eef"
        hash = "ee34d62e136a04e2eaf84b8daa12c9f2233a366af83081a38c3c973ab5e2c40f"

        id = "a5caab93-7b94-59d7-bbca-f9863e81b9e5"
    strings:
        //strings from private rule capa_bin_files
        $dex1 = "dex\n0"
        $dex2 = "dey\n0"
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

        //strings from private rule capa_php_new_long
        // no <?=
        $new_php2 = "<?php" nocase wide ascii
        $new_php3 = "<script language=\"php" nocase wide ascii
        $php_short = "<?"

        //strings from private rule capa_php_dynamic
        // php variable regex from https://www.php.net/manual/en/language.variables.basics.php
        $dynamic1 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(\$/ wide ascii
        $dynamic2 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\("/ wide ascii
        $dynamic3 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\('/ wide ascii
        $dynamic4 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(str/ wide ascii
        $dynamic5 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(\)/ wide ascii
        $dynamic6 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(@/ wide ascii
        $dynamic7 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(base64_decode/ wide ascii
        $dynamic8 = "eval(" wide ascii

        //strings from private rule capa_gen_sus

        // these strings are just a bit suspicious, so several of them are needed, depending on filesize
        $gen_bit_sus1  = /:\s{0,20}eval}/ nocase wide ascii
        $gen_bit_sus2  = /\.replace\(\/\w\/g/ nocase wide ascii
        $gen_bit_sus6  = "self.delete"
        $gen_bit_sus9  = "\"cmd /c" nocase
        $gen_bit_sus10 = "\"cmd\"" nocase
        $gen_bit_sus11 = "\"cmd.exe" nocase
        $gen_bit_sus12 = "%comspec%" wide ascii
        $gen_bit_sus13 = "%COMSPEC%" wide ascii
        //TODO:$gen_bit_sus12 = ".UserName" nocase
        $gen_bit_sus18 = "Hklm.GetValueNames();" nocase
        // bonus string for proxylogon exploiting webshells
        $gen_bit_sus19 = "http://schemas.microsoft.com/exchange/" wide ascii
        $gen_bit_sus21 = "\"upload\"" wide ascii
        $gen_bit_sus22 = "\"Upload\"" wide ascii
        $gen_bit_sus23 = "UPLOAD" fullword wide ascii
        $gen_bit_sus24 = "fileupload" wide ascii
        $gen_bit_sus25 = "file_upload" wide ascii
        $gen_bit_sus27 = "zuncomp" wide ascii
        $gen_bit_sus28 = "ase6" wide ascii
        // own base64 or base32 func
        $gen_bit_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword wide ascii
        $gen_bit_sus29b = "abcdefghijklmnopqrstuvwxyz234567" fullword wide ascii
        $gen_bit_sus30 = "serv-u" wide ascii
        $gen_bit_sus31 = "Serv-u" wide ascii
        $gen_bit_sus32 = "Army" fullword wide ascii
        // single letter paramweter
        $gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword wide ascii
        $gen_bit_sus34 = "Content-Transfer-Encoding: Binary" wide ascii
        $gen_bit_sus35 = "crack" fullword wide ascii

        $gen_bit_sus44 = "<pre>" wide ascii
        $gen_bit_sus45 = "<PRE>" wide ascii
        $gen_bit_sus46 = "shell_" wide ascii
        //fp: $gen_bit_sus47 = "Shell" fullword wide ascii
        $gen_bit_sus50 = "bypass" wide ascii
        $gen_bit_sus52 = " ^ $" wide ascii
        $gen_bit_sus53 = ".ssh/authorized_keys" wide ascii
        $gen_bit_sus55 = /\w'\.'\w/ wide ascii
        $gen_bit_sus56 = /\w\"\.\"\w/ wide ascii
        $gen_bit_sus57 = "dumper" wide ascii
        $gen_bit_sus59 = "'cmd'" wide ascii
        $gen_bit_sus60 = "\"execute\"" wide ascii
        $gen_bit_sus61 = "/bin/sh" wide ascii
        $gen_bit_sus62 = "Cyber" wide ascii
        $gen_bit_sus63 = "portscan" fullword wide ascii
        $gen_bit_sus65 = "whoami" fullword wide ascii
        $gen_bit_sus67 = "$password='" fullword wide ascii
        $gen_bit_sus68 = "$password=\"" fullword wide ascii
        $gen_bit_sus69 = "$cmd" fullword wide ascii
        $gen_bit_sus70 = "\"?>\"." fullword wide ascii
        $gen_bit_sus71 = "Hacking" fullword wide ascii
        $gen_bit_sus72 = "hacking" fullword wide ascii
        $gen_bit_sus73 = ".htpasswd" wide ascii
        $gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/ wide ascii
        $gen_bit_sus99 = "$password = " wide ascii
        $gen_bit_sus100 = "();$" wide ascii

        // very suspicious strings, one is enough
        $gen_much_sus7  = "Web Shell" nocase
        $gen_much_sus8  = "WebShell" nocase
        $gen_much_sus3  = "hidded shell"
        $gen_much_sus4  = "WScript.Shell.1" nocase
        $gen_much_sus5  = "AspExec"
        $gen_much_sus14 = "\\pcAnywhere\\" nocase
        $gen_much_sus15 = "antivirus" nocase
        $gen_much_sus16 = "McAfee" nocase
        $gen_much_sus17 = "nishang"
        $gen_much_sus18 = "\"unsafe" fullword wide ascii
        $gen_much_sus19 = "'unsafe" fullword wide ascii
        $gen_much_sus24 = "exploit" fullword wide ascii
        $gen_much_sus25 = "Exploit" fullword wide ascii
        $gen_much_sus26 = "TVqQAAMAAA" wide ascii
        $gen_much_sus30 = "Hacker" wide ascii
        $gen_much_sus31 = "HACKED" fullword wide ascii
        $gen_much_sus32 = "hacked" fullword wide ascii
        $gen_much_sus33 = "hacker" wide ascii
        $gen_much_sus34 = "grayhat" nocase wide ascii
        $gen_much_sus35 = "Microsoft FrontPage" wide ascii
        $gen_much_sus36 = "Rootkit" wide ascii
        $gen_much_sus37 = "rootkit" wide ascii
        $gen_much_sus38 = "/*-/*-*/" wide ascii
        $gen_much_sus39 = "u\"+\"n\"+\"s" wide ascii
        $gen_much_sus40 = "\"e\"+\"v" wide ascii
        $gen_much_sus41 = "a\"+\"l\"" wide ascii
        $gen_much_sus42 = "\"+\"(\"+\"" wide ascii
        $gen_much_sus43 = "q\"+\"u\"" wide ascii
        $gen_much_sus44 = "\"u\"+\"e" wide ascii
        $gen_much_sus45 = "/*//*/" wide ascii
        $gen_much_sus46 = "(\"/*/\"" wide ascii
        $gen_much_sus47 = "eval(eval(" wide ascii
        // self remove
        $gen_much_sus48 = "unlink(__FILE__)" wide ascii
        $gen_much_sus49 = "Shell.Users" wide ascii
        $gen_much_sus50 = "PasswordType=Regular" wide ascii
        $gen_much_sus51 = "-Expire=0" wide ascii
        $gen_much_sus60 = "_=$$_" wide ascii
        $gen_much_sus61 = "_=$$_" wide ascii
        $gen_much_sus62 = "++;$" wide ascii
        $gen_much_sus63 = "++; $" wide ascii
        $gen_much_sus64 = "_.=$_" wide ascii
        $gen_much_sus70 = "-perm -04000" wide ascii
        $gen_much_sus71 = "-perm -02000" wide ascii
        $gen_much_sus72 = "grep -li password" wide ascii
        $gen_much_sus73 = "-name config.inc.php" wide ascii
        // touch without parameters sets the time to now, not malicious and gives fp
        $gen_much_sus75 = "password crack" wide ascii
        $gen_much_sus76 = "mysqlDll.dll" wide ascii
        $gen_much_sus77 = "net user" wide ascii
        $gen_much_sus80 = "fopen(\".htaccess\",\"w" wide ascii
        $gen_much_sus81 = /strrev\(['"]/ wide ascii
        $gen_much_sus82 = "PHPShell" fullword wide ascii
        $gen_much_sus821= "PHP Shell" fullword wide ascii
        $gen_much_sus83 = "phpshell" fullword wide ascii
        $gen_much_sus84 = "PHPshell" fullword wide ascii
        $gen_much_sus87 = "deface" wide ascii
        $gen_much_sus88 = "Deface" wide ascii
        $gen_much_sus89 = "backdoor" wide ascii
        $gen_much_sus90 = "r00t" fullword wide ascii
        $gen_much_sus91 = "xp_cmdshell" fullword wide ascii
        $gen_much_sus92 = "DEFACE" fullword wide ascii
        $gen_much_sus93 = "Bypass" fullword wide ascii
        $gen_much_sus94 = /eval\s{2,20}\(/ nocase wide ascii
        $gen_much_sus100 = "rot13" wide ascii
        $gen_much_sus101 = "ini_set('error_log'" wide ascii
        $gen_much_sus102 = "base64_decode(base64_decode(" wide ascii
        $gen_much_sus103 = "=$_COOKIE;" wide ascii
        // {1}.$ .. |{9}.$
        $gen_much_sus104 = { C0 A6 7B 3? 7D 2E 24 }
        $gen_much_sus105 = "$GLOBALS[\"__" wide ascii
        // those calculations don't make really sense :)
        $gen_much_sus106 = ")-0)" wide ascii
        $gen_much_sus107 = "-0)+" wide ascii
        $gen_much_sus108 = "+0)+" wide ascii
        $gen_much_sus109 = "+(0/" wide ascii
        $gen_much_sus110 = "+(0+" wide ascii
        $gen_much_sus111 = "extract($_REQUEST)" wide ascii
        $gen_much_sus112 = "<?php\t\t\t\t\t\t\t\t\t\t\t" wide ascii
        $gen_much_sus113 = "\t\t\t\t\t\t\t\t\t\t\textract" wide ascii
        $gen_much_sus114 = "\" .\"" wide ascii
        $gen_much_sus115 = "end($_POST" wide ascii

        $weevely1 = /';\n\$\w\s?=\s?'/ wide ascii
        $weevely2 = /';\x0d\n\$\w\s?=\s?'/ wide ascii // same with \r\n
        $weevely3 = /';\$\w{1,2}='/ wide ascii
        $weevely4 = "str_replace" fullword wide ascii

        $gif = { 47 49 46 38 }

        $fp1 = "# Some examples from obfuscated malware:" ascii
        $fp2 = "* @package   PHP_CodeSniffer" ascii
        $fp3 = ".jQuery===" ascii
        $fp4 = "* @param string $lstat encoded LStat string" ascii
        $fp5 = "' => array('horde:"
        $fp6 = "$messages['fileuploaderror'] = '"
    condition:
        //any of them or
        not (
            uint16(0) == 0x5a4d or
            // <?xml
            uint32be(0) == 0x3c3f786d  or
            // <?XML
            uint32be(0) == 0x3c3f584d  or
            $dex1 at 0 or
            $dex2 at 0 or
            $pack at 0 or
            // fp on jar with zero compression
            uint16(0) == 0x4b50 or
            1 of ($fp*)
        )
        and (
            any of ( $new_php* ) or
            $php_short at 0
        )
        and (
            any of ( $dynamic* )
        )
        and
            (
            $gif at 0 or
        (
            (
                filesize < 1KB and
                (
                    1 of ( $gen_much_sus* )
                )
            ) or (
                filesize < 2KB and
                (
                    ( #weevely1 + #weevely2 + #weevely3 ) > 2 and
                    #weevely4 > 1
                )
            ) or (
                filesize < 4000 and
                (
                    1 of ( $gen_much_sus* ) or
                    2 of ( $gen_bit_sus* )
                )
            ) or (
                filesize < 20KB and
                (
                    2 of ( $gen_much_sus* ) or
                    4 of ( $gen_bit_sus* )
                )
            ) or (
                filesize < 50KB and
                (
                    3 of ( $gen_much_sus* ) or
                    5 of ( $gen_bit_sus* )
                )
            ) or (
                filesize < 100KB and
                (
                    3 of ( $gen_much_sus* ) or
                    6 of ( $gen_bit_sus* )
                )
            ) or (
                filesize < 160KB and
                (
                    3 of ( $gen_much_sus* ) or
                    7 of ( $gen_bit_sus* ) or
                    (
                        // php files which use strings in the full ascii8 spectrum have a much hioher deviation than normal php-code
                        // e.g. 4057005718bb18b51b02d8b807265f8df821157ac47f78ace77f21b21fc77232
                        math.deviation(500, filesize-500, 89.0) > 70
                        // uncomment and include an "and" above for debugging, also import on top of file. needs yara 4.2.0
                        //console.log("high deviation") and
                        //console.log(math.deviation(500, filesize-500, 89.0))
                    )
                    // TODO: requires yara 4.2.0 so wait a bit until that's more common
                    //or
                    //(
                        // big file and just one line = minified
                        //filesize > 10KB and
                        //math.count(0x0A) < 2
                    //)
                )
            ) or (
                filesize < 500KB and
                (
                    4 of ( $gen_much_sus* ) or
                    8 of ( $gen_bit_sus* ) or
                    #gen_much_sus104 > 4

                )
            )
        ) or (
            // file shouldn't be too small to have big enough data for math.entropy
            filesize > 2KB and filesize < 1MB and
            (
                (
                    // base64 :
                    // ignore first and last 500bytes because they usually contain code for decoding and executing
                    math.entropy(500, filesize-500) >= 5.7 and
                    // encoded text has a higher mean than text or code because it's missing the spaces and special chars with the low numbers
                    math.mean(500, filesize-500) > 80 and
                    // deviation of base64 is ~20 according to CyberChef_v9.21.0.html#recipe=Generate_Lorem_Ipsum(3,'Paragraphs')To_Base64('A-Za-z0-9%2B/%3D')To_Charcode('Space',10)Standard_Deviation('Space')
                    // lets take a bit more because it might not be pure base64 also include some xor, shift, replacement, ...
                    // 89 is the mean of the base64 chars
                    math.deviation(500, filesize-500, 89.0) < 23
                ) or (
                    // gzinflated binary sometimes used in php webshells
                    // ignore first and last 500bytes because they usually contain code for decoding and executing
                    math.entropy(500, filesize-500) >= 7.7 and
                    // encoded text has a higher mean than text or code because it's missing the spaces and special chars with the low numbers
                    math.mean(500, filesize-500) > 120 and
                    math.mean(500, filesize-500) < 136 and
                    // deviation of base64 is ~20 according to CyberChef_v9.21.0.html#recipe=Generate_Lorem_Ipsum(3,'Paragraphs')To_Base64('A-Za-z0-9%2B/%3D')To_Charcode('Space',10)Standard_Deviation('Space')
                    // lets take a bit more because it might not be pure base64 also include some xor, shift, replacement, ...
                    // 89 is the mean of the base64 chars
                    math.deviation(500, filesize-500, 89.0) > 65
                )
            )
        )
        )
}

rule WEBSHELL_PHP_Encoded_Big {
    meta:
        description = "PHP webshell using some kind of eval with encoded blob to decode, which is checked with YARAs math.entropy module"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/02/07"
        modified = "2024-12-16"
        score = 50
        hash = "1d4b374d284c12db881ba42ee63ebce2759e0b14"
        hash = "fc0086caee0a2cd20609a05a6253e23b5e3245b8"
        hash = "b15b073801067429a93e116af1147a21b928b215"
        hash = "74c92f29cf15de34b8866db4b40748243fb938b4"
        hash = "042245ee0c54996608ff8f442c8bafb8"

        id = "c3bb7b8b-c554-5802-8955-c83722498f8b"
    strings:

        //strings from private rule capa_php_new
        $new_php1 = /<\?=[\w\s@$]/ wide ascii
        $new_php2 = "<?php" nocase wide ascii
        $new_php3 = "<script language=\"php" nocase wide ascii
        $php_short = "<?"

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload2 = /\bexec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload3 = /\bshell_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload4 = /\bpassthru[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload6 = /\bpopen[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload7 = /\bproc_open[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload9 = /\bassert[\n\t ]{0,500}\([^)0]/ nocase wide ascii
        $cpayload10 = /\bpreg_replace[\n\t ]{0,500}\([^\)]{1,100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload20 = /\bcreate_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]{0,500}[,}\)]/ nocase wide ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]{0,500}(\([^\)]|\/\*)/ nocase wide ascii
        $m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
        // TODO backticks

    condition:
        //console.log(math.entropy(500, filesize-500)) and
        //console.log(math.mean(500, filesize-500)) and
        //console.log(math.deviation(500, filesize-500, 89.0)) and
        //any of them or
        filesize < 1000KB and (
            any of ( $new_php* ) or
        $php_short at 0
        )
        and (
            any of ( $cpayload* ) or
        all of ( $m_cpayload_preg_filter* )
        )
        and (
            // file shouldn't be too small to have big enough data for math.entropy
            filesize > 2KB and
        (
            // base64 :
            // ignore first and last 500bytes because they usually contain code for decoding and executing
            math.entropy(500, filesize-500) >= 5.7 and
            // encoded text has a higher mean than text or code because it's missing the spaces and special chars with the low numbers
            math.mean(500, filesize-500) > 80 and
            // deviation of base64 is ~20 according to CyberChef_v9.21.0.html#recipe=Generate_Lorem_Ipsum(3,'Paragraphs')To_Base64('A-Za-z0-9%2B/%3D')To_Charcode('Space',10)Standard_Deviation('Space')
            // lets take a bit more because it might not be pure base64 also include some xor, shift, replacement, ...
            // 89 is the mean of the base64 chars
            math.deviation(500, filesize-500, 89.0) < 24
        ) or (
            // gzinflated binary sometimes used in php webshells
            // ignore first and last 500bytes because they usually contain code for decoding and executing
            math.entropy(500, filesize-500) >= 7.7 and
            // encoded text has a higher mean than text or code because it's missing the spaces and special chars with the low numbers
            math.mean(500, filesize-500) > 120 and
            math.mean(500, filesize-500) < 136 and
            // deviation of base64 is ~20 according to CyberChef_v9.21.0.html#recipe=Generate_Lorem_Ipsum(3,'Paragraphs')To_Base64('A-Za-z0-9%2B/%3D')To_Charcode('Space',10)Standard_Deviation('Space')
            // lets take a bit more because it might not be pure base64 also include some xor, shift, replacement, ...
            // 89 is the mean of the base64 chars
            math.deviation(500, filesize-500, 89.0) > 65
        )
        )

}

rule WEBSHELL_PHP_Generic_Backticks {
    meta:
        description = "Generic PHP webshell which uses backticks directly on user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "339f32c883f6175233f0d1a30510caa52fdcaa37"
        hash = "8db86ad90883cd208cf86acd45e67c03f994998804441705d690cb6526614d00"
        hash = "af987b0eade03672c30c095cee0c7c00b663e4b3c6782615fb7e430e4a7d1d75"
        hash = "67339f9e70a17af16cf51686918cbe1c0604e129950129f67fe445eaff4b4b82"
        hash = "144e242a9b219c5570973ca26d03e82e9fbe7ba2773305d1713288ae3540b4ad"
        hash = "8db86ad90883cd208cf86acd45e67c03f994998804441705d690cb6526614d00"

        id = "b2f1d8d0-8668-5641-8ce9-c8dd71f51f58"
    strings:
        $backtick = /`\s*\{?\$(_POST\[|_GET\[|_REQUEST\[|_SERVER\['HTTP_)/ wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and $backtick and filesize < 200
}

rule WEBSHELL_PHP_Generic_Backticks_OBFUSC {
    meta:
        description = "Generic PHP webshell which uses backticks directly on user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "23dc299f941d98c72bd48659cdb4673f5ba93697"
        hash = "e3f393a1530a2824125ecdd6ac79d80cfb18fffb89f470d687323fb5dff0eec1"
        hash = "1e75914336b1013cc30b24d76569542447833416516af0d237c599f95b593f9b"
        hash = "8db86ad90883cd208cf86acd45e67c03f994998804441705d690cb6526614d00"

        id = "5ecb329f-0755-536d-8bfa-e36158474a0b"
    strings:
        $s1 = /echo[\t ]{0,500}\(?`\$/ wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 500 and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and $s1
}

rule WEBSHELL_PHP_Strings_SUSP {
    meta:
        description = "typical webshell strings, suspicious"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/01/12"
        modified = "2023-07-05"
        score = 50
        hash = "0dd568dbe946b5aa4e1d33eab1decbd71903ea04"
        hash = "dde2bdcde95730510b22ae8d52e4344997cb1e74"
        hash = "499db4d70955f7d40cf5cbaf2ecaf7a2"
        hash = "281b66f62db5caab2a6eb08929575ad95628a690"
        hash = "1ab3ae4d613b120f9681f6aa8933d66fa38e4886"

        id = "25f25df5-4398-562b-9383-e01ccb17e8de"
    strings:
        $sstring1 = "eval(\"?>\"" nocase wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

        //strings from private rule capa_php_input
        $inp1 = "php://input" wide ascii
        $inp2 = /_GET\s?\[/ wide ascii
        // for passing $_GET to a function
        $inp3 = /\(\s?\$_GET\s?\)/ wide ascii
        $inp4 = /_POST\s?\[/ wide ascii
        $inp5 = /\(\s?\$_POST\s?\)/ wide ascii
        $inp6 = /_REQUEST\s?\[/ wide ascii
        $inp7 = /\(\s?\$_REQUEST\s?\)/ wide ascii
        // PHP automatically adds all the request headers into the $_SERVER global array, prefixing each header name by the "HTTP_" string, so e.g. @eval($_SERVER['HTTP_CMD']) will run any code in the HTTP header CMD
        $inp15 = "_SERVER['HTTP_" wide ascii
        $inp16 = "_SERVER[\"HTTP_" wide ascii
        $inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ wide ascii
        $inp18 = "array_values($_SERVER)" wide ascii
        $inp19 = /file_get_contents\("https?:\/\// wide ascii

    condition:
        filesize < 700KB and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and not (
            any of ( $gfp* )
        )
        and
        ( 1 of ( $sstring* ) and (
            any of ( $inp* )
        )
        )
}

rule WEBSHELL_PHP_In_Htaccess {
    meta:
        description = "Use Apache .htaccess to execute php code inside .htaccess"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-07-05"
        hash = "c026d4512a32d93899d486c6f11d1e13b058a713"
        hash = "d79e9b13a32a9e9f3fa36aa1a4baf444bfd2599a"
        hash = "e1d1091fee6026829e037b2c70c228344955c263"
        hash = "c026d4512a32d93899d486c6f11d1e13b058a713"
        hash = "8c9e65cd3ef093cd9c5b418dc5116845aa6602bc92b9b5991b27344d8b3f7ef2"

        id = "0f5edff9-22b2-50c9-ae81-72698ea8e7db"
    strings:
        $hta = "AddType application/x-httpd-php .htaccess" wide ascii

    condition:
        filesize <100KB and $hta
}

rule WEBSHELL_PHP_Function_Via_Get {
    meta:
        description = "Webshell which sends eval/assert via GET"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/09"
        modified = "2023-04-05"
        hash = "ce739d65c31b3c7ea94357a38f7bd0dc264da052d4fd93a1eabb257f6e3a97a6"
        hash = "d870e971511ea3e082662f8e6ec22e8a8443ca79"
        hash = "73fa97372b3bb829835270a5e20259163ecc3fdbf73ef2a99cb80709ea4572be"

        id = "5fef1063-2f9f-516e-86f6-cfd98bb05e6e"
    strings:
        $sr0 = /\$_GET\s?\[.{1,30}\]\(\$_GET\s?\[/ wide ascii
        $sr1 = /\$_POST\s?\[.{1,30}\]\(\$_GET\s?\[/ wide ascii
        $sr2 = /\$_POST\s?\[.{1,30}\]\(\$_POST\s?\[/ wide ascii
        $sr3 = /\$_GET\s?\[.{1,30}\]\(\$_POST\s?\[/ wide ascii
        $sr4 = /\$_REQUEST\s?\[.{1,30}\]\(\$_REQUEST\s?\[/ wide ascii
        $sr5 = /\$_SERVER\s?\[HTTP_.{1,30}\]\(\$_SERVER\s?\[HTTP_/ wide ascii

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

    condition:
        filesize < 500KB and not (
            any of ( $gfp* )
        )
        and any of ( $sr* )
}

rule WEBSHELL_PHP_Writer {
    meta:
        description = "PHP webshell which only writes an uploaded file to disk"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/04/17"
        modified = "2023-07-05"
        score = 50
        hash = "ec83d69512aa0cc85584973f5f0850932fb1949fb5fb2b7e6e5bbfb121193637"
        hash = "407c15f94a33232c64ddf45f194917fabcd2e83cf93f38ee82f9720e2635fa64"
        hash = "988b125b6727b94ce9a27ea42edc0ce282c5dfeb"
        hash = "0ce760131787803bbef216d0ee9b5eb062633537"
        hash = "20281d16838f707c86b1ff1428a293ed6aec0e97"

        id = "05bb3e0c-69b2-5176-a3eb-e6ba2d72a205"
    strings:
        $sus3 = "'upload'" wide ascii
        $sus4 = "\"upload\"" wide ascii
        $sus5 = "\"Upload\"" wide ascii
        $sus6 = "gif89" wide ascii
        //$sus13= "<textarea " wide ascii
        $sus16= "Army" fullword wide ascii
        $sus17= "error_reporting( 0 )" wide ascii
        $sus18= "' . '" wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_input
        $inp1 = "php://input" wide ascii
        $inp2 = /_GET\s?\[/ wide ascii
        // for passing $_GET to a function
        $inp3 = /\(\s?\$_GET\s?\)/ wide ascii
        $inp4 = /_POST\s?\[/ wide ascii
        $inp5 = /\(\s?\$_POST\s?\)/ wide ascii
        $inp6 = /_REQUEST\s?\[/ wide ascii
        $inp7 = /\(\s?\$_REQUEST\s?\)/ wide ascii
        // PHP automatically adds all the request headers into the $_SERVER global array, prefixing each header name by the "HTTP_" string, so e.g. @eval($_SERVER['HTTP_CMD']) will run any code in the HTTP header CMD
        $inp15 = "_SERVER['HTTP_" wide ascii
        $inp16 = "_SERVER[\"HTTP_" wide ascii
        $inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ wide ascii
        $inp18 = "array_values($_SERVER)" wide ascii
        $inp19 = /file_get_contents\("https?:\/\// wide ascii

        //strings from private rule capa_php_write_file
        $php_multi_write1 = "fopen(" wide ascii
        $php_multi_write2 = "fwrite(" wide ascii
        $php_write1 = "move_uploaded_file" fullword wide ascii
        $php_write2 = "copy" fullword wide ascii

    condition:
        //any of them or
        (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and (
            any of ( $inp* )
        )
        and (
        any of ( $php_write* ) or
        all of ( $php_multi_write* )
        )
        and
        (
            filesize < 400 or
            (
                filesize < 4000 and 1 of ( $sus* )
            )
        )
}

rule WEBSHELL_JSP_ReGeorg {
    meta:
        description = "Webshell regeorg JSP version"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        reference = "https://github.com/sensepost/reGeorg"
        hash = "6db49e43722080b5cd5f07e058a073ba5248b584"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/24"
        modified = "2024-12-09"
        score = 75
        hash = "650eaa21f4031d7da591ebb68e9fc5ce5c860689"
        hash = "00c86bf6ce026ccfaac955840d18391fbff5c933"
        hash = "6db49e43722080b5cd5f07e058a073ba5248b584"
        hash = "9108a33058aa9a2fb6118b719c5b1318f33f0989"

        id = "cbb90005-d8f8-5c64-85d1-29e466f48c25"
    strings:
        $jgeorg1 = "request" fullword wide ascii
        $jgeorg2 = "getHeader" fullword wide ascii
        $jgeorg3 = "X-CMD" fullword wide ascii
        $jgeorg4 = "X-STATUS" fullword wide ascii
        $jgeorg5 = "socket" fullword wide ascii
        $jgeorg6 = "FORWARD" fullword wide ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

    condition:
        filesize < 300KB and (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            ($cjsp_short1 and $cjsp_short2 in ( filesize-100..filesize )) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and all of ( $jgeorg* )
}

rule WEBSHELL_JSP_HTTP_Proxy {
    meta:
        description = "Webshell JSP HTTP proxy"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        hash = "2f9b647660923c5262636a5344e2665512a947a4"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/24"
        modified = "2024-12-09"
        hash = "97c1e2bf7e769d3fc94ae2fc74ac895f669102c6"
        hash = "2f9b647660923c5262636a5344e2665512a947a4"

        id = "55be246e-30a8-52ed-bc5f-507e63bbfe16"
    strings:
        $jh1 = "OutputStream" fullword wide ascii
        $jh2 = "InputStream"  wide ascii
        $jh3 = "BufferedReader" fullword wide ascii
        $jh4 = "HttpRequest" fullword wide ascii
        $jh5 = "openConnection" fullword wide ascii
        $jh6 = "getParameter" fullword wide ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

    condition:
        filesize < 10KB and (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            ($cjsp_short1 and $cjsp_short2 in ( filesize-100..filesize )) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and all of ( $jh* )
}

rule WEBSHELL_JSP_Writer_Nano {
    meta:
        description = "JSP file writer"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/24"
        modified = "2024-12-09"
        hash = "ac91e5b9b9dcd373eaa9360a51aa661481ab9429"
        hash = "c718c885b5d6e29161ee8ea0acadb6e53c556513"
        hash = "9f1df0249a6a491cdd5df598d83307338daa4c43"
        hash = "5e241d9d3a045d3ade7b6ff6af6c57b149fa356e"

        id = "422a18f2-d6d4-5b42-be15-1eafe44e01cf"
    strings:
        // writting file to disk
        $payload1 = ".write" wide ascii
        $payload2 = "getBytes" fullword wide ascii
        $payload3 = ".decodeBuffer" wide ascii
        $payload4 = "FileOutputStream" fullword wide ascii

        // writting using java logging, e.g 9f1df0249a6a491cdd5df598d83307338daa4c43
        $logger1 = "getLogger" fullword ascii wide
        $logger2 = "FileHandler" fullword ascii wide
        $logger3 = "addHandler" fullword ascii wide

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

        $jw_sus1 = /getParameter\("."\)/ ascii wide // one char param
        $jw_sus4 = "yoco" fullword ascii wide // webshell coder

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

    condition:
        //any of them or
        (
            any of ( $input* ) and
            any of ( $req* )
        ) and (
            filesize < 200 or
            (
                filesize < 1000 and
                any of ( $jw_sus* )
            )
        )
        and (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            ($cjsp_short1 and $cjsp_short2 in ( filesize-100..filesize )) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and (
            2 of ( $payload* ) or
            all of ( $logger* )
            )
}

rule EXT_WEBSHELL_JSP_Generic_Tiny
{
    meta:
        description = "Generic JSP webshell tiny"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2024-12-16"
        hash = "8fd343db0442136e693e745d7af1018a99b042af"
        hash = "87c3ac9b75a72187e8bc6c61f50659435dbdc4fde6ed720cebb93881ba5989d8"
        hash = "1aa6af726137bf261849c05d18d0a630d95530588832aadd5101af28acc034b5"

        id = "fad14524-de44-52ea-95e6-3e5de3138926"
    strings:
        $payload1 = "ProcessBuilder" fullword wide ascii
        $payload2 = "URLClassLoader" fullword wide ascii
        // Runtime.getRuntime().exec(
        $payload_rt1 = "Runtime" fullword wide ascii
        $payload_rt2 = "getRuntime" fullword wide ascii
        $payload_rt3 = "exec" fullword wide ascii

        $jg_sus1 = "xe /c" ascii wide // of cmd.exe /c
        $jg_sus2 = /getParameter\("."\)/ ascii wide // one char param
        $jg_sus3 = "</pre>" ascii wide // webshells like fixed font wide
        $jg_sus4 = "BASE64Decoder" fullword ascii wide

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

        // no web input but fixed command to create reverse shell
        $fixed_cmd1 = "bash -i >& /dev/" ascii wide

        $fp1 = "Find Security Bugs is a plugin that aims to help security audit.</Details>"
    condition:
        //any of them or
        (
            (
                filesize < 1000 and
                any of ( $jg_sus* )
            ) or
            filesize < 250
        ) and (
            $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            ($cjsp_short1 and $cjsp_short2 in ( filesize-100..filesize )) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and (
                (
                    any of ( $input* ) and
                    any of ( $req* )
                ) or (
                    any of ( $fixed_cmd* )
                )
        )
        and
        ( 1 of ( $payload* ) or all of ( $payload_rt* ) )
        and not any of ( $fp* )
}

rule WEBSHELL_JSP_Generic {
    meta:
        description = "Generic JSP webshell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2025-08-18"
        hash = "4762f36ca01fb9cda2ab559623d2206f401fc0b1"
        hash = "bdaf9279b3d9e07e955d0ce706d9c42e4bdf9aa1"
        hash = "ee9408eb923f2d16f606a5aaac7e16b009797a07"

        id = "7535ade8-fc65-5558-a72c-cc14c3306390"
    strings:
        $susp0 = "cmd" fullword nocase ascii wide
        $susp1 = "command" fullword nocase ascii wide
        $susp2 = "shell" fullword nocase ascii wide
        $susp3 = "download" fullword nocase ascii wide
        $susp4 = "upload" fullword nocase ascii wide
        $susp5 = "Execute" fullword nocase ascii wide
        $susp6 = "\"pwd\"" ascii wide
        $susp7 = "\"</pre>" ascii wide
        $susp8 = /\\u00\d\d\\u00\d\d\\u00\d\d\\u00\d\d/ ascii wide
        $susp9 = "*/\\u00" ascii wide // perfect match of 2 obfuscation methods: /**/\u00xx :)

        $fp1 = "command = \"cmd.exe /c set\";"

        //strings from private rule capa_bin_files
        $dex1 = "dex\n0"
        $dex2 = "dey\n0"
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

        //strings from private rule capa_jsp_payload
        $payload1 = "ProcessBuilder" fullword ascii wide
        $payload2 = "processCmd" fullword ascii wide
        // Runtime.getRuntime().exec(
        $rt_payload1 = "Runtime" fullword ascii wide
        $rt_payload2 = "getRuntime" fullword ascii wide
        $rt_payload3 = "exec" fullword ascii wide

    condition:
        filesize < 300KB and not (
        uint16(0) == 0x5a4d or
        $dex1 at 0 or
        $dex2 at 0 or
        $pack at 0 or
        // fp on jar with zero compression
        uint16(0) == 0x4b50
        )
        and (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            ($cjsp_short1 and $cjsp_short2 in ( filesize-100..filesize )) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and (
            any of ( $input* ) and
            any of ( $req* )
        )
        and (
        1 of ( $payload* ) or
        all of ( $rt_payload* )
        )
        and not any of ( $fp* ) and any of ( $susp* )
}

rule WEBSHELL_JSP_Generic_Base64 {
    meta:
        description = "Generic JSP webshell with base64 encoded payload"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/24"
        modified = "2025-08-18"
        hash = "8b5fe53f8833df3657ae2eeafb4fd101c05f0db0"
        hash = "1b916afdd415dfa4e77cecf47321fd676ba2184d"

        id = "2eabbad2-7d10-573a-9120-b9b763fa2352"
    strings:
        // Runtime
        $one1 = "SdW50aW1l" wide ascii
        $one2 = "J1bnRpbW" wide ascii
        $one3 = "UnVudGltZ" wide ascii
        $one4 = "IAdQBuAHQAaQBtAGUA" wide ascii
        $one5 = "SAHUAbgB0AGkAbQBlA" wide ascii
        $one6 = "UgB1AG4AdABpAG0AZQ" wide ascii
        // exec
        $two1 = "leGVj" wide ascii
        $two2 = "V4ZW" wide ascii
        $two3 = "ZXhlY" wide ascii
        $two4 = "UAeABlAGMA" wide ascii
        $two5 = "lAHgAZQBjA" wide ascii
        $two6 = "ZQB4AGUAYw" wide ascii
        // ScriptEngineFactory
        $three1 = "TY3JpcHRFbmdpbmVGYWN0b3J5" wide ascii
        $three2 = "NjcmlwdEVuZ2luZUZhY3Rvcn" wide ascii
        $three3 = "U2NyaXB0RW5naW5lRmFjdG9ye" wide ascii
        $three4 = "MAYwByAGkAcAB0AEUAbgBnAGkAbgBlAEYAYQBjAHQAbwByAHkA" wide ascii
        $three5 = "TAGMAcgBpAHAAdABFAG4AZwBpAG4AZQBGAGEAYwB0AG8AcgB5A" wide ascii
        $three6 = "UwBjAHIAaQBwAHQARQBuAGcAaQBuAGUARgBhAGMAdABvAHIAeQ" wide ascii


        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_bin_files
        $dex1 = "dex\n0"
        $dex2 = "dey\n0"
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

    condition:
        (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            ($cjsp_short1 and $cjsp_short2 in ( filesize-100..filesize )) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and not (
        uint16(0) == 0x5a4d or
        $dex1 at 0 or
        $dex2 at 0 or
        $pack at 0 or
        // fp on jar with zero compression
        uint16(0) == 0x4b50
        )
        and filesize < 300KB and
        ( any of ( $one* ) and any of ( $two* ) or any of ( $three* ) )
}

rule WEBSHELL_JSP_Generic_ProcessBuilder {
    meta:
        description = "Generic JSP webshell which uses processbuilder to execute user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "82198670ac2072cd5c2853d59dcd0f8dfcc28923"
        hash = "c05a520d96e4ebf9eb5c73fc0fa446ceb5caf343"
        hash = "347a55c174ee39ec912d9107e971d740f3208d53af43ea480f502d177106bbe8"
        hash = "d0ba29b646274e8cda5be1b940a38d248880d9e2bba11d994d4392c80d6b65bd"

        id = "2a7c5f44-24a1-5f43-996e-945c209b79b1"
    strings:
        $exec = "ProcessBuilder" fullword wide ascii
        $start = "start" fullword wide ascii

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

    condition:
        filesize < 2000 and (
            any of ( $input* ) and
            any of ( $req* )
        )
        and $exec and $start
}

rule WEBSHELL_JSP_Generic_Reflection {
    meta:
        description = "Generic JSP webshell which uses reflection to execute user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2024-12-09"
        hash = "62e6c6065b5ca45819c1fc049518c81d7d165744"
        hash = "bf0ff88cbb72c719a291c722ae3115b91748d5c4920afe7a00a0d921d562e188"

        id = "806ffc8b-1dc8-5e28-ae94-12ad3fee18cd"
    strings:
        $ws_exec = "invoke" fullword wide ascii
        $ws_class = "Class" fullword wide ascii
        $fp1 = "SOAPConnection"
        $fp2 = "/CORBA/"

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

        $cj_encoded1 = "\"java.util.Base64$Decoder\"" ascii wide
    condition:
        //any of them or
        all of ( $ws_* ) and (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            ($cjsp_short1 and $cjsp_short2 in ( filesize-100..filesize )) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and not any of ( $fp* ) and
        (
            // either some kind of code input from the a web request ...
            filesize < 10KB and
            (
                any of ( $input* ) and
                any of ( $req* )
            )
            or
            (
                // ... or some encoded payload (which might get code input from a web request)
                filesize < 30KB and
                any of ( $cj_encoded* ) and
                // base64 :
                // ignore first and last 500bytes because they usually contain code for decoding and executing
                math.entropy(500, filesize-500) >= 5.5 and
                // encoded text has a higher mean than text or code because it's missing the spaces and special chars with the low numbers
                math.mean(500, filesize-500) > 80 and
                // deviation of base64 is ~20 according to CyberChef_v9.21.0.html#recipe=Generate_Lorem_Ipsum(3,'Paragraphs')To_Base64('A-Za-z0-9%2B/%3D')To_Charcode('Space',10)Standard_Deviation('Space')
                // lets take a bit more because it might not be pure base64 also include some xor, shift, replacement, ...
                // 89 is the mean of the base64 chars
                math.deviation(500, filesize-500, 89.0) < 23
            )
        )

}

rule WEBSHELL_JSP_Generic_Classloader {
    meta:
        description = "Generic JSP webshell which uses classloader to execute user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        hash = "6b546e78cc7821b63192bb8e087c133e8702a377d17baaeb64b13f0dd61e2347"
        date = "2021/01/07"
        modified = "2024-12-09"
        hash = "f3a7e28e1c38fa5d37811bdda1d6b0893ab876023d3bd696747a35c04141dcf0"
        hash = "8ea2a25344e6094fa82dfc097bbec5f1675f6058f2b7560deb4390bcbce5a0e7"
        hash = "b9ea1e9f91c70160ee29151aa35f23c236d220c72709b2b75123e6fa1da5c86c"
        hash = "80211c97f5b5cd6c3ab23ae51003fd73409d273727ba502d052f6c2bd07046d6"
        hash = "8e544a5f0c242d1f7be503e045738369405d39731fcd553a38b568e0889af1f2"

        id = "037e6b24-9faf-569b-bb52-dbe671ab2e87"
    strings:
        $exec = "extends ClassLoader" wide ascii
        $class = "defineClass" fullword wide ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

    condition:
        //any of them or
        (
            (
                $cjsp_short1 at 0 or
                    any of ( $cjsp_long* ) or
                    ($cjsp_short1 and $cjsp_short2 in ( filesize-100..filesize )) or
                (
                    $cjsp_short2 and (
                        $cjsp_short1 in ( 0..1000 ) or
                        $cjsp_short1 in ( filesize-1000..filesize )
                    )
                )
            )
            and (
                any of ( $input* ) and
                any of ( $req* )
            )
            and $exec and $class
        ) and
        (
            filesize < 10KB or
            (
                filesize < 50KB and
                (
                    // filled with same characters
                    math.entropy(500, filesize-500) <= 1 or
                    // filled with random garbage
                    math.entropy(500, filesize-500) >= 7.7
                )
            )
        )
}

rule WEBSHELL_JSP_Generic_Encoded_Shell {
    meta:
        description = "Generic JSP webshell which contains cmd or /bin/bash encoded in ascii ord"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-07-05"
        hash = "3eecc354390d60878afaa67a20b0802ce5805f3a9bb34e74dd8c363e3ca0ea5c"
        hash = "f6c2112e3a25ec610b517ff481675b2ce893cb9f"
        hash = "62e6c6065b5ca45819c1fc049518c81d7d165744"

        id = "359949d7-1793-5e13-9fdc-fe995ae12117"
    strings:
        $sj0 = /\{ ?47, 98, 105, 110, 47, 98, 97, 115, 104/ wide ascii
        $sj1 = /\{ ?99, 109, 100}/ wide ascii
        $sj2 = /\{ ?99, 109, 100, 46, 101, 120, 101/ wide ascii
        $sj3 = /\{ ?47, 98, 105, 110, 47, 98, 97/ wide ascii
        $sj4 = /\{ ?106, 97, 118, 97, 46, 108, 97, 110/ wide ascii
        $sj5 = /\{ ?101, 120, 101, 99 }/ wide ascii
        $sj6 = /\{ ?103, 101, 116, 82, 117, 110/ wide ascii

    condition:
        filesize <300KB and any of ($sj*)
}

rule WEBSHELL_JSP_NetSpy {
    meta:
        description = "JSP netspy webshell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/24"
        modified = "2024-12-09"
        hash = "94d1aaabde8ff9b4b8f394dc68caebf981c86587"
        hash = "3870b31f26975a7cb424eab6521fc9bffc2af580"

        id = "41f5c171-878d-579f-811d-91d74f7e3e24"
    strings:
        $scan1 = "scan" nocase wide ascii
        $scan2 = "port" nocase wide ascii
        $scan3 = "web" fullword nocase wide ascii
        $scan4 = "proxy" fullword nocase wide ascii
        $scan5 = "http" fullword nocase wide ascii
        $scan6 = "https" fullword nocase wide ascii
        $write1 = "os.write" fullword wide ascii
        $write2 = "FileOutputStream" fullword wide ascii
        $write3 = "PrintWriter" fullword wide ascii
        $http = "java.net.HttpURLConnection" fullword wide ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

    condition:
        filesize < 30KB and (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            ($cjsp_short1 and $cjsp_short2 in ( filesize-100..filesize )) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and (
            any of ( $input* ) and
            any of ( $req* )
        )
        and 4 of ( $scan* ) and 1 of ( $write* ) and $http
}

rule WEBSHELL_JSP_By_String {
    meta:
        description = "JSP Webshells which contain unique strings, lousy rule for low hanging fruits. Most are catched by other rules in here but maybe these catch different versions."
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/09"
        modified = "2025-08-18"
        hash = "e9060aa2caf96be49e3b6f490d08b8a996c4b084"
        hash = "4c2464503237beba54f66f4a099e7e75028707aa"
        hash = "06b42d4707e7326aff402ecbb585884863c6351a"
        hash = "dada47c052ec7fcf11d5cfb25693bc300d3df87de182a254f9b66c7c2c63bf2e"
        hash = "f9f6c696c1f90df6421cd9878a1dec51a62e91b4b4f7eac4920399cb39bc3139"
        hash = "f1d8360dc92544cce301949e23aad6eb49049bacf9b7f54c24f89f7f02d214bb"
        hash = "1d1f26b1925a9d0caca3fdd8116629bbcf69f37f751a532b7096a1e37f4f0076"
        hash = "850f998753fde301d7c688b4eca784a045130039512cf51292fcb678187c560b"

        id = "8d64e40b-5583-5887-afe1-b926d9880913"
    strings:
        $jstring1 = "<title>Boot Shell</title>" wide ascii
        $jstring2 = "String oraPWD=\"" wide ascii
        $jstring3 = "Owned by Chinese Hackers!" wide ascii
        $jstring4 = "AntSword JSP" wide ascii
        $jstring5 = "JSP Webshell</" wide ascii
        $jstring6 = "motoME722remind2012" wide ascii
        $jstring7 = "EC(getFromBase64(toStringHex(request.getParameter(\"password" wide ascii
        $jstring8 = "http://jmmm.com/web/index.jsp" wide ascii
        $jstring9 = "list.jsp = Directory & File View" wide ascii
        $jstring10 = "jdbcRowSet.setDataSourceName(request.getParameter(" wide ascii
        $jstring11 = "Mr.Un1k0d3r RingZer0 Team" wide ascii
        $jstring12 = "MiniWebCmdShell" fullword wide ascii
        $jstring13 = "pwnshell.jsp" fullword wide ascii
        $jstring14 = "session set &lt;key&gt; &lt;value&gt; [class]<br>"  wide ascii
        $jstring15 = "Runtime.getRuntime().exec(request.getParameter(" nocase wide ascii
        $jstring16 = "GIF98a<%@page" wide ascii
        $jstring17 = "Tas9er" fullword wide ascii
        $jstring18 = "uu0028\\u" wide ascii //obfuscated /
        $jstring19 = "uu0065\\u" wide ascii //obfuscated e
        $jstring20 = "uu0073\\u" wide ascii //obfuscated s
        $jstring21 = /\\uuu{0,50}00/ wide ascii //obfuscated via javas unlimited amount of u in \uuuuuu
        $jstring22 = /[\w\.]\\u(FFFB|FEFF|FFF9|FFFA|200C|202E|202D)[\w\.]/ wide ascii // java ignores the unicode Interlinear Annotation Terminator inbetween any command
        $jstring23 = "\"e45e329feb5d925b\"" wide ascii
        $jstring24 = "u<![CDATA[n" wide ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_bin_files
        $dex1 = "dex\n0"
        $dex2 = "dey\n0"
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

    condition:
        //any of them or
        not (
            uint16(0) == 0x5a4d or
            $dex1 at 0 or
            $dex2 at 0 or
            $pack at 0 or
            // fp on jar with zero compression
            uint16(0) == 0x4b50
        ) and
        (
            (
                filesize < 100KB and
                (
                    $cjsp_short1 at 0 or
                    any of ( $cjsp_long* ) or
                    ($cjsp_short1 and $cjsp_short2 in ( filesize-100..filesize )) or
                    (
                        $cjsp_short2 and (
                            $cjsp_short1 in ( 0..1000 ) or
                            $cjsp_short1 in ( filesize-1000..filesize )
                        )
                    )
                )
                and any of ( $jstring* )
            ) or (
                filesize < 500KB and
                (
                    #jstring21 > 20 or
                    $jstring18 or
                    $jstring19 or
                    $jstring20

                )
            )
        )
}

rule WEBSHELL_JSP_Input_Upload_Write {
    meta:
        description = "JSP uploader which gets input, writes files and contains \"upload\""
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/24"
        modified = "2024-12-09"
        hash = "ef98ca135dfb9dcdd2f730b18e883adf50c4ab82"
        hash = "583231786bc1d0ecca7d8d2b083804736a3f0a32"
        hash = "19eca79163259d80375ebebbc440b9545163e6a3"

        id = "bbf26edd-88b7-5ec5-a16e-d96a086dcd19"
    strings:
        $upload = "upload" nocase wide ascii
        $write1 = "os.write" fullword wide ascii
        $write2 = "FileOutputStream" fullword wide ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

    condition:
        filesize < 10KB and (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            ($cjsp_short1 and $cjsp_short2 in ( filesize-100..filesize )) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and (
            any of ( $input* ) and
            any of ( $req* )
        )
        and $upload and 1 of ( $write* )
}

rule WEBSHELL_Generic_OS_Strings : FILE {
    meta:
        description = "typical webshell strings"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/01/12"
        modified = "2024-12-09"
        score = 50
        hash = "d5bfe40283a28917fcda0cefd2af301f9a7ecdad"
        hash = "fd45a72bda0a38d5ad81371d68d206035cb71a14"
        hash = "b4544b119f919d8cbf40ca2c4a7ab5c1a4da73a3"
        hash = "569259aafe06ba3cef9e775ee6d142fed6edff5f"
        hash = "48909d9f4332840b4e04b86f9723d7427e33ac67"
        hash = "0353ae68b12b8f6b74794d3273967b530d0d526f"
        id = "ea85e415-4774-58ac-b063-0f5eb535ec49"
    strings:
        $fp1 = "http://evil.com/" wide ascii
        $fp2 = "denormalize('/etc/shadow" wide ascii
      $fp3 = "vim.org>"

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_os_strings
        // windows = nocase
        $w1 = "net localgroup administrators" nocase wide ascii
        $w2 = "net user" nocase wide ascii
        $w3 = "/add" nocase wide ascii
        // linux stuff, case sensitive:
        $l1 = "/etc/shadow" wide ascii
        $l2 = "/etc/ssh/sshd_config" wide ascii
        $take_two1 = "net user" nocase wide ascii
        $take_two2 = "/add" nocase wide ascii

    condition:
        filesize < 70KB and
        ( (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        or (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        or (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            ($cjsp_short1 and $cjsp_short2 in ( filesize-100..filesize )) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        ) and (
            filesize < 300KB and
        not uint16(0) == 0x5a4d and (
            all of ( $w* ) or
            all of ( $l* ) or
            2 of ( $take_two* )
        )
        )
        and not any of ( $fp* )
}

rule WEBSHELL_In_Image {
    meta:
        description = "Webshell in GIF, PNG or JPG"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        hash = "d4fde4e691db3e70a6320e78657480e563a9f87935af873a99db72d6a9a83c78"
        hash = "84938133ee6e139a2816ab1afc1c83f27243c8ae76746ceb2e7f20649b5b16a4"
        hash = "52b918a64afc55d28cd491de451bb89c57bce424f8696d6a94ec31fb99b17c11"
        date = "2021/02/27"
        modified = "2024-03-11"
        score = 55

        id = "b1185b69-9b08-5925-823a-829fee6fa4cf"
    strings:
        $png = { 89 50 4E 47 }
        $jpg = { FF D8 FF E0 }
        $gif = "GIF8" wide ascii // doesn't make sense for a GIF but some webshells are utf8 :)
        $gif2 = "gif89" // not a valid gif but used in webshells
        $gif3 = "Gif89" // not a valid gif but used in webshells
        // MS access
        $mdb = { 00 01 00 00 53 74 }
        //$mdb = { 00 01 00 00 53 74 61 6E 64 61 72 64 20 4A 65 74 20 44 42 }

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload2 = /\bexec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload3 = /\bshell_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload4 = /\bpassthru[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload5 = /\bsystem[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload6 = /\bpopen[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload7 = /\bproc_open[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload9 = /\bassert[\n\t ]{0,500}\([^)0]/ nocase wide ascii
        $cpayload10 = /\bpreg_replace[\n\t ]{0,500}\([^\)]{1,100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload20 = /\bcreate_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]{0,500}[,}\)]/ nocase wide ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]{0,500}(\([^\)]|\/\*)/ nocase wide ascii
        $m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
        // TODO backticks

        //strings from private rule capa_php_write_file
        $php_multi_write1 = "fopen(" wide ascii
        $php_multi_write2 = "fwrite(" wide ascii
        $php_write1 = "move_uploaded_file" fullword wide ascii

        //strings from private rule capa_jsp
        $cjsp1 = "<%" ascii wide
        $cjsp2 = "<jsp:" ascii wide
        $cjsp3 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp4 = "/jstl/core" ascii wide

        //strings from private rule capa_jsp_payload
        $payload1 = "ProcessBuilder" fullword ascii wide
        $payload2 = "processCmd" fullword ascii wide
        // Runtime.getRuntime().exec(
        $rt_payload1 = "Runtime" fullword ascii wide
        $rt_payload2 = "getRuntime" fullword ascii wide
        $rt_payload3 = "exec" fullword ascii wide

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_payload
        $asp_payload0  = "eval_r" fullword nocase wide ascii
        $asp_payload1  = /\beval\s/ nocase wide ascii
        $asp_payload2  = /\beval\(/ nocase wide ascii
        $asp_payload3  = /\beval\"\"/ nocase wide ascii
        // var Fla = {'E':eval};  Fla.E(code)
        $asp_payload4  = /:\s{0,10}eval\b/ nocase wide ascii
        $asp_payload8  = /\bexecute\s?\(/ nocase wide ascii
        $asp_payload9  = /\bexecute\s[\w"]/ nocase wide ascii
        $asp_payload11 = "WSCRIPT.SHELL" fullword nocase wide ascii
        $asp_payload13 = "ExecuteGlobal" fullword nocase wide ascii
        $asp_payload14 = "ExecuteStatement" fullword nocase wide ascii
        $asp_payload15 = "ExecuteStatement" fullword nocase wide ascii
        $asp_multi_payload_one1 = "CreateObject" nocase fullword wide ascii
        $asp_multi_payload_one2 = "addcode" fullword wide ascii
        $asp_multi_payload_one3 = /\.run\b/ wide ascii
        $asp_multi_payload_two1 = "CreateInstanceFromVirtualPath" fullword wide ascii
        $asp_multi_payload_two2 = "ProcessRequest" fullword wide ascii
        $asp_multi_payload_two3 = "BuildManager" fullword wide ascii
        $asp_multi_payload_three1 = "System.Diagnostics" wide ascii
        $asp_multi_payload_three2 = "Process" fullword wide ascii
        $asp_multi_payload_three3 = ".Start" wide ascii
        // this is about "MSXML2.DOMDocument" but since that's easily obfuscated, lets not search for it
        $asp_multi_payload_four1 = "CreateObject" fullword nocase wide ascii
        $asp_multi_payload_four2 = "TransformNode" fullword nocase wide ascii
        $asp_multi_payload_four3 = "loadxml" fullword nocase wide ascii

        // execute cmd.exe /c with arguments using ProcessStartInfo
        $asp_multi_payload_five1 = "ProcessStartInfo" fullword nocase wide ascii
        $asp_multi_payload_five2 = ".Start" nocase wide ascii
        $asp_multi_payload_five3 = ".Filename" nocase wide ascii
        $asp_multi_payload_five4 = ".Arguments" nocase wide ascii


        //strings from private rule capa_asp_write_file
        // $asp_write1 = "ADODB.Stream" wide ascii # just a string, can be easily obfuscated
        $asp_always_write1 = /\.write/ nocase wide ascii
        $asp_always_write2 = /\.swrite/ nocase wide ascii
        //$asp_write_way_one1 = /\.open\b/ nocase wide ascii
        $asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
        $asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
        $asp_cr_write1 = "CreateObject(" nocase wide ascii
        $asp_cr_write2 = "CreateObject (" nocase wide ascii
        $asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
        $asp_streamwriter2 = "filestream" fullword nocase wide ascii

    condition:
        // reduce fp
        //any of them or
        filesize < 5MB and
        // also check for GIF8 at 0x3 because some folks write their webshell in a text editor and have a BOM in front of GIF8 (which probably wouldn't be a valif GIF anymore :)
        ( $png at 0 or $jpg at 0 or $gif at 0 or $gif at 3 or $gif2 at 0 or $gif2 at 3 or $gif3 at 0 or $mdb at 0 ) and
        ( ( (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and
        ( (
            any of ( $cpayload* ) or
        all of ( $m_cpayload_preg_filter* )
        )
        or (
        any of ( $php_write* ) or
        all of ( $php_multi_write* )
        )
        ) ) or
        ( (
            any of ( $cjsp* )
        )
        and (
        1 of ( $payload* ) or
        all of ( $rt_payload* )
        )
        ) or
        ( (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and
        ( (
            any of ( $asp_payload* ) or
        all of ( $asp_multi_payload_one* ) or
        all of ( $asp_multi_payload_two* ) or
        all of ( $asp_multi_payload_three* ) or
        all of ( $asp_multi_payload_four* ) or
        all of ( $asp_multi_payload_five* )
        )
        or (
        any of ( $asp_always_write* ) and
        (
            any of ( $asp_write_way_one* ) and
            any of ( $asp_cr_write* )
        ) or (
            any of ( $asp_streamwriter* )
        )
        )
        ) ) )
}

rule WEBSHELL_Mixed_OBFUSC {
   meta:
      description = "Detects webshell with mixed obfuscation commands"
      author = "Arnim Rupp (https://github.com/ruppde)"
      reference = "Internal Research"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      date = "2023-01-28"
      modified = "2023-04-05"
      hash1 = "8c4e5c6bdfcc86fa27bdfb075a7c9a769423ec6d53b73c80cbc71a6f8dd5aace"
      hash2 = "78f2086b6308315f5f0795aeaa75544128f14889a794205f5fc97d7ca639335b"
      hash3 = "3bca764d44074820618e1c831449168f220121698a7c82e9909f8eab2e297cbd"
      hash4 = "b26b5e5cba45482f486ff7c75b54c90b7d1957fd8e272ddb4b2488ec65a2936e"
      hash5 = "e217be2c533bfddbbdb6dc6a628e0d8756a217c3ddc083894e07fd3a7408756c"
      score = 50
      id = "dcb4054b-0c87-5cd0-9297-7fd5f2e37437"
   strings:
      $s1 = "rawurldecode/*" ascii
      $s2 = "preg_replace/*" ascii
      $s3 = " __FILE__/*" ascii
      $s4 = "strlen/*" ascii
      $s5 = "str_repeat/*" ascii
      $s6 = "basename/*" ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 200KB and ( 4 of them ))
}

rule WEBSHELL_Cookie_Post_Obfuscation {
    meta:
        description = "Detects webshell using cookie POST"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2023-01-28"
        modified = "2023-04-05"
        license = "https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md"
        hash = "d08a00e56feb78b7f6599bad6b9b1d8626ce9a6ea1dfdc038358f4c74e6f65c9"
        hash = "2ce5c4d31682a5a59b665905a6f698c280451117e4aa3aee11523472688edb31"
        hash = "ff732d91a93dfd1612aed24bbb4d13edb0ab224d874f622943aaeeed4356c662"
        hash = "a3b64e9e065602d2863fcab641c75f5d8ec67c8632db0f78ca33ded0f4cea257"
        hash = "d41abce305b0dc9bd3a9feb0b6b35e8e39db9e75efb055d0b1205a9f0c89128e"
        hash = "333560bdc876fb0186fae97a58c27dd68123be875d510f46098fc5a61615f124"
        hash = "2efdb79cdde9396ff3dd567db8876607577718db692adf641f595626ef64d3a4"
        hash = "e1bd3be0cf525a0d61bf8c18e3ffaf3330c1c27c861aede486fd0f1b6930f69a"
        hash = "f8cdedd21b2cc29497896ec5b6e5863cd67cc1a798d929fd32cdbb654a69168a"

        id = "cc5ded80-5e58-5b25-86d1-1c492042c740"
    strings:
        $s1 = "]($_COOKIE, $_POST) as $"
        $s2 = "function"
        $s3 = "Array"
    condition:
    ( uint16(0) == 0x3f3c and filesize < 100KB and ( all of them ))
}

