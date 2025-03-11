//
// Created by witch on 3/11/25.
//

#ifndef COM_H
#define COM_H

#endif //COM_H

void serial_putc(char c) {
    volatile uint8_t* serial_port = (volatile uint8_t*)0x3f8;
    while ( !(*serial_port & 0x20) );
    *serial_port = c;
}

void serial_print(const char* str) {
    while (*str) {
        serial_putc(*str++);
    }
}

void serial_print_hex(uint32_t val) {
    const char hex[] = "0123456789ABCDEF";
    serial_print("0x");
    for (int i = 28; i >= 0; i -= 4) {
        serial_putc(hex[(val >> i) & 0xf]);
    }
}