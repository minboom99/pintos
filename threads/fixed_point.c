#include <stdint.h>
#include "threads/fixed_point.h"

/* int_to_fp() converts n to fixed point. */
int int_to_fp(int n)
{
    return n * F;
}

/* fp_to_int_round() converts x to integer (rounding toward zero). */
int fp_to_int_round(int x)
{
    return x / F;
}

/* fp_to_int() converts x to integer (rounding to nearest). */
int fp_to_int(int x)
{
    if (x >= 0)
    {
        return (x + F / 2) / F;
    }
    else
    {
        return (x - F / 2) / F;
    }
}

/* add_fp adds x and y. */
int add_fp(int x, int y)
{
    return x + y;
}

/* add_mixed() adds x(fp) and n(int). */
int add_mixed(int x, int n)
{
    return x + n * F;
}

/* sup_fp() subtracts y from x. */
int sub_fp(int x, int y)
{
    return x - y;
}

/* sub_mixed() subtracts n(int) from x(fp). */
int sub_mixed(int x, int n)
{
    return x - n * F;
}

/* mult_fp() multiplies x by y. */
int mult_fp(int x, int y)
{
    return ((int64_t)x) * y / F;
}

/* mult_mixed() multiplies x(fp) by n(int). */
int mult_mixed(int x, int n)
{
    return x * n;
}

/* div_fp() divides x by y */
int div_fp(int x, int y)
{
    return ((int64_t)x) * F / y;
}

/* div_mixed divides x(fp) by n(int)*/
int div_mixed(int x, int n)
{
    return x / n;
}