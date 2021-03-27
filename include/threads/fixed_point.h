#ifndef THREADS_FIXEDPOINT_H
#define THREADS_FIXEDPOINT_H

#define F (1 << 14) // fixed point 1

int int_to_fp (int);
int fp_to_int_round (int);
int fp_to_int (int);
int add_fp (int, int);
int add_mixed (int, int);
int sub_fp (int, int);
int sub_mixed (int, int);
int mult_fp (int, int);
int mult_mixed (int, int);
int div_fp (int, int);
int div_mixed (int, int);


#endif /* threads/fixed_point.h */