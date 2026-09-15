extern int milestone6_dependency(void);

int milestone6_consumer(void) { return milestone6_dependency(); }

#ifndef MILESTONE6_SHARED
int main(void) { return milestone6_consumer(); }
#endif
