#include "wr/sdp.h"

#include <string.h>

/* ------------------------------------------------------------------------- */
/* Attributes                                                                */
/* ------------------------------------------------------------------------- */

const wr_sdp_attr *wr_sdp_attr_find(const wr_sdp_attr_vec *attrs,
                                    wr_span_c name)
{
    if (!attrs) {
        return NULL;
    }
    for (size_t i = 0; i < attrs->len; ++i) {
        if (wr_span_c_case_eq(attrs->data[i].name, name)) {
            return &attrs->data[i];
        }
    }
    return NULL;
}

const wr_sdp_attr *wr_sdp_attr_find_last(const wr_sdp_attr_vec *attrs,
                                         wr_span_c name)
{
    if (!attrs) {
        return NULL;
    }
    for (size_t i = attrs->len; i > 0; --i) {
        if (wr_span_c_case_eq(attrs->data[i - 1u].name, name)) {
            return &attrs->data[i - 1u];
        }
    }
    return NULL;
}

bool wr_sdp_attr_add(wr_sdp_attr_vec *attrs, wr_span_c name, wr_span_c value)
{
    if (!attrs || !attrs->a) {
        return false;
    }
    wr_sdp_attr a;
    a.name = name;
    a.value = value;
    return wr_sdp_attr_vec_push(attrs, a);
}

bool wr_sdp_attr_set(wr_sdp_attr_vec *attrs, wr_span_c name, wr_span_c value)
{
    if (!attrs) {
        return false;
    }
    for (size_t i = 0; i < attrs->len; ++i) {
        if (wr_span_c_case_eq(attrs->data[i].name, name)) {
            attrs->data[i].value = value;
            return true;
        }
    }
    return wr_sdp_attr_add(attrs, name, value);
}

