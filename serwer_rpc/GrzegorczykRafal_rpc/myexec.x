struct data_in {
    char command[1000];
    char argument[1000];
};

struct data_out {
    char data_out[2048];
};

program PROG {
 version MYEXEC{
  data_out MYEXEC (data_in) = 1;
 }=1;
}= 0x31240000;