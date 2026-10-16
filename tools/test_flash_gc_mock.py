#!/usr/bin/env python3
"""Compile actual Flash GC function bodies from main/rules.c against a host mock.
Tests erase ranges, active-slot protection, duplicate cleanup avoidance,
interrupted erases and both-slot retirement without ESP-IDF.
Requires Python 3 and a C compiler named gcc; does not test real Flash.
"""
from pathlib import Path
import subprocess
import tempfile
root=Path(__file__).resolve().parents[1]
s=(root/'main/rules.c').read_text()
body=s[s.index('static bool erase_old_partition('):s.index('/* ---- download ')]
prefix='''#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#define SEC 4096u
#define BLOCK 65536u
#define TAG "test"
#define ESP_OK 0
#define ESP_LOGE(...) do {} while(0)
#define ESP_LOGI(...) do {} while(0)
typedef int esp_err_t;
typedef struct { size_t size; unsigned char *data; } esp_partition_t;
typedef struct cJSON { int valueint; double valuedouble; bool valid; struct cJSON *slot; struct cJSON *gc_gen; double generation; } cJSON;
static esp_partition_t *g_slot[2], *g_staging;
static int g_active=-1;
static struct {char phase[24];} g_st;
static unsigned n_erase, fail_at, saved;
static void flash_lock(void) {}
static void flash_unlock(void) {}
static void vTaskDelay(int x) {(void)x;}
static const char *esp_err_to_name(int x) {(void)x; return "IO";}
static esp_err_t esp_partition_erase_range(const esp_partition_t *p, size_t off, size_t count) {
    n_erase++;
    if(n_erase==fail_at || (off%SEC) || (count%SEC) || off+count>p->size) return -1;
    memset(p->data+off,0xff,count);return ESP_OK;
}
static cJSON *cJSON_GetObjectItem(const cJSON *obj, const char *key) {
    if(!strcmp(key,"flash_gc_slot")) return obj->slot;
    if(!strcmp(key,"flash_gc_gen")) return obj->gc_gen;
    return NULL;
}
static bool cJSON_IsNumber(const cJSON *v) { return v && v->valid; }
static double jget_num(const cJSON *obj,const char *key) {
    if(!strcmp(key,"gen"))return obj->generation;
    return 0;
}
static void jset_num(cJSON *obj,const char *key, double value) {
    if(!strcmp(key,"flash_gc_slot")) {obj->slot->valueint=(int)value;obj->slot->valid=true;}
    if(!strcmp(key,"flash_gc_gen")) {obj->gc_gen->valuedouble=value;obj->gc_gen->valid=true;}
}
static bool substat_save(cJSON *obj){(void)obj;saved++;return true;}
'''
checks='''
int main(void) {
    esp_partition_t p0={4u<<20,calloc(4u<<20,1)}, p1={4u<<20,calloc(4u<<20,1)}, st={ (9u<<19),calloc(9u<<19,1)};
    if(!p0.data||!p1.data||!st.data) return 10;
    g_slot[0]=&p0;g_slot[1]=&p1;g_staging=&st;
    memset(p0.data,0xaa,p0.size);memset(p1.data,0xbb,p1.size);memset(st.data,0xcc,st.size);
    cJSON slot={0},gen={0},root={.slot=&slot,.gc_gen=&gen,.generation=7.0};
    g_active=1;
    if(!cleanup_obsolete_flash(&root,1))return 1;
    for(size_t i=0;i<p0.size;i++) if(p0.data[i]!=0xff) return 2;
    for(size_t i=0;i<st.size;i++) if(st.data[i]!=0xff) return 3;
    for(size_t i=0;i<p1.size;i++) if(p1.data[i]!=0xbb) return 4;
    unsigned erased=n_erase;
    if(!cleanup_obsolete_flash(&root,1)||n_erase!=erased)return 5;
    root.generation=8.0; slot.valid=false; gen.valid=false;
    fail_at=n_erase+2;
    if(cleanup_obsolete_flash(&root,1))return 6;
    if(slot.valid||gen.valid)return 7;
    fail_at=0;
    if(!cleanup_obsolete_flash(&root,1))return 8;
    for(size_t i=0;i<p1.size;i++) if(p1.data[i]!=0xbb) return 9;
    memset(p0.data,0xaa,p0.size);memset(p1.data,0xbb,p1.size);memset(st.data,0xcc,st.size);
    g_active=-1;root.generation=9.0;slot.valid=false;gen.valid=false;
    if(!cleanup_obsolete_flash(&root,-1))return 11;
    for(size_t i=0;i<p0.size;i++) if(p0.data[i]!=0xff) return 12;
    for(size_t i=0;i<p1.size;i++) if(p1.data[i]!=0xff) return 13;
    for(size_t i=0;i<st.size;i++) if(st.data[i]!=0xff) return 14;
    printf("flash GC mock OK: erased %u sectors/blocks, saved %u times\\n",n_erase,saved);
    free(p0.data);free(p1.data);free(st.data);
    return 0;
}
'''
code=prefix+body+checks
with tempfile.TemporaryDirectory(prefix='esp32flashgc_') as tmp:
    p=Path(tmp)/'test_flash_gc.c'; p.write_text(code)
    out=Path(tmp)/'test_flash_gc'
    subprocess.run(['gcc','-std=gnu11','-O2','-Wall','-Wextra','-Werror',
                    '-Wno-unused-parameter','-Wno-unused-function',str(p),'-o',str(out)],check=True)
    subprocess.run([str(out)],check=True)
