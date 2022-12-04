from pwn import * 
class IO_FILE:
    def __init__(self) -> None:
        self._flags = 0xfbad0000
        self._IO_read_ptr = 0
        self._IO_read_end = 0
        self._IO_read_base = 0
        self._IO_write_base = 0
        self._IO_write_ptr = 0
        self._IO_write_end = 0
        self._IO_buf_base = 0
        self._IO_buf_end = 0
        self._IO_save_base = 0
        self._IO_backup_base = 0
        self._save_end = 0
        self._markers = 0
        self._chain = 0
        self._fileno = 0
        self._flags2 = 0
        self._old_offset = 0xffffffffffffffff
        self._cur_column = 0
        self._vtable_offset = 0
        self._shortbuf = 0
        self._lock = 0         
        self._offset = 0xffffffffffffffff
        self._codecvt = 0 
        self._wide_data = 0
        self._freeres_list = 0
        self._freeres_buf = 0
        self.__pad5 = 0
        self._mode = 0
        self._unused2 = 0
        self.vtable = 0
    def get_bytes(self) -> bytes:
        return  p64(self._flags) + \
                p64(self._IO_read_ptr) + \
                p64(self._IO_read_end) + \
                p64(self._IO_read_base) + \
                p64(self._IO_write_base) + \
                p64(self._IO_write_ptr) + \
                p64(self._IO_write_end) + \
                p64(self._IO_buf_base) + \
                p64(self._IO_buf_end) + \
                p64(self._IO_save_base) + \
                p64(self._IO_backup_base) + \
                p64(self._save_end) + \
                p64(self._markers) + \
                p64(self._chain) + \
                p32(self._fileno) + \
                p32(self._flags2) + \
                p64(self._old_offset) + \
                p16(self._cur_column) + \
                p8(self._vtable_offset) + \
                p8(self._shortbuf) + \
                p32(0) + \
                p64(self._lock) + \
                p64(self._offset) + \
                p64(self._codecvt) + \
                p64(self._wide_data) + \
                p64(self._freeres_list) + \
                p64(self._freeres_buf) + \
                p64(self.__pad5) + \
                p32(0) + \
                p32(self._mode) + \
                p32(self._unused2)*5 + \
                p64(self.vtable)