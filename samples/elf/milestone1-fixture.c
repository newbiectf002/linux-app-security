/* Trusted static-inspection fixture. The scanner must never execute this file. */
int milestone1_exported_symbol(void) {
    return 7;
}

int main(void) {
    return milestone1_exported_symbol();
}
