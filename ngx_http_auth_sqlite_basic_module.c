
/*
 * Copyright (C) Kunal Bharati
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <sqlite3.h>

#define NGX_HTTP_AUTH_BUF_SIZE  2048

typedef struct {
    ngx_str_t                 realm;
    ngx_str_t                 sqlite_table;
    ngx_str_t                 sqlite_user;
    ngx_str_t                 sqlite_passwd;
    ngx_str_t                 sqlite_db_file;
} ngx_http_auth_sqlite_basic_loc_conf_t;


static ngx_int_t ngx_http_auth_sqlite_basic_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_sqlite_basic_set_realm(ngx_http_request_t *r,
    ngx_str_t *realm);
static void *ngx_http_auth_sqlite_basic_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_auth_sqlite_basic_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_auth_sqlite_basic_init(ngx_conf_t *cf);
static char *ngx_http_auth_sqlite_basic(ngx_conf_t *cf, void *post, void *data);


static ngx_conf_post_handler_pt  ngx_http_auth_sqlite_basic_p = ngx_http_auth_sqlite_basic;

static ngx_command_t  ngx_http_auth_sqlite_basic_commands[] = {

    { ngx_string("auth_sqlite_basic"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_sqlite_basic_loc_conf_t, realm),
      &ngx_http_auth_sqlite_basic_p },

    { ngx_string("auth_sqlite_basic_database_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_sqlite_basic_loc_conf_t, sqlite_db_file),
      NULL },

    { ngx_string("auth_sqlite_basic_database_table"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_sqlite_basic_loc_conf_t, sqlite_table),
      NULL },

    { ngx_string("auth_sqlite_basic_table_user_column"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_sqlite_basic_loc_conf_t, sqlite_user),
      NULL },

    { ngx_string("auth_sqlite_basic_table_passwd_column"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_sqlite_basic_loc_conf_t, sqlite_passwd),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_auth_sqlite_basic_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_auth_sqlite_basic_init,              /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_auth_sqlite_basic_create_loc_conf,   /* create location configuration */
    ngx_http_auth_sqlite_basic_merge_loc_conf     /* merge location configuration */
};


ngx_module_t  ngx_http_auth_sqlite_basic_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_sqlite_basic_module_ctx,       /* module context */
    ngx_http_auth_sqlite_basic_commands,          /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_auth_sqlite_basic_handler(ngx_http_request_t *r)
{
    ngx_int_t                        rc;
    ngx_http_auth_sqlite_basic_loc_conf_t  *alcf;

    /* Sqlite info */
    ngx_int_t sqlite_return_value;
    sqlite3_stmt *sqlite_stmt;
    sqlite3 *sqlite_handle;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_sqlite_basic_module);

    if (alcf->realm.len == 0 || alcf->sqlite_db_file.len == 0) {
        return NGX_DECLINED;
    }

    rc = ngx_http_auth_basic_user(r);

    if (rc == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "no user/password was provided for basic authentication");
        return ngx_http_auth_sqlite_basic_set_realm(r, &alcf->realm);
    }

    if (rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    sqlite_return_value = sqlite3_open((char *) alcf->sqlite_db_file.data, &sqlite_handle);

    if(sqlite_return_value) {
	ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0, "Opening \"%s\" database failed", alcf->sqlite_db_file.data);
	return rc;
    }

    char* select_query = (char *) malloc (500);

    //FIXME: Dirty work done here as r->headers_in.user.data values is username:password. Following code reads the r->headers_in.user.data upto ":"
    ngx_uint_t i = 0;
    ngx_str_t login, encoded; // = (char *) malloc(r->headers_in.user.data.len);

    encoded = r->headers_in.authorization->value;
    encoded.len -= sizeof("Basic ") - 1;
    encoded.data += sizeof("Basic ") - 1;

    login.len = ngx_base64_decoded_length(encoded.len);
    login.data = ngx_pnalloc(r->pool, login.len + 1);

    while (r->headers_in.user.data[i] != ':') {
	login.data[i] = r->headers_in.user.data[i];
	i++;
      }

    login.data[i] = '\0';
    // End  //

    sprintf(select_query, "select * from %s where %s = \"%s\" and %s = \"%s\"", alcf->sqlite_table.data, alcf->sqlite_user.data, login.data, alcf->sqlite_passwd.data, r->headers_in.passwd.data);

    const char* tail;
    sqlite_return_value = sqlite3_prepare_v2(sqlite_handle, select_query, strlen(select_query), &sqlite_stmt, &tail);

    if (sqlite_return_value != SQLITE_OK) {
	ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0,  "Unable to fetch data from \"%s\" database", alcf->sqlite_db_file.data);
	return ngx_http_auth_sqlite_basic_set_realm(r, &alcf->realm);
      }

    sqlite_return_value = sqlite3_step(sqlite_stmt);

    if(sqlite_return_value == SQLITE_ROW) {
	sqlite3_close(sqlite_handle);
	return rc;
      }
    
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s was not found in %s table", r->headers_in.user.data, alcf->sqlite_table.data);
    
    sqlite3_close(sqlite_handle);

    return ngx_http_auth_sqlite_basic_set_realm(r, &alcf->realm);
}


static ngx_int_t
ngx_http_auth_sqlite_basic_set_realm(ngx_http_request_t *r, ngx_str_t *realm)
{
    r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.www_authenticate == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.www_authenticate->hash = 1;
    ngx_str_set(&r->headers_out.www_authenticate->key, "WWW-Authenticate");
    r->headers_out.www_authenticate->value = *realm;

    return NGX_HTTP_UNAUTHORIZED;
}


static void *
ngx_http_auth_sqlite_basic_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_auth_sqlite_basic_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_sqlite_basic_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static char *
ngx_http_auth_sqlite_basic_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_auth_sqlite_basic_loc_conf_t  *prev = parent;
    ngx_http_auth_sqlite_basic_loc_conf_t  *conf = child;

    if (conf->realm.data == NULL) {
        conf->realm = prev->realm;
    }

    if (conf->sqlite_db_file.len == 0) {
        conf->sqlite_db_file = prev->sqlite_db_file;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_auth_sqlite_basic_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_auth_sqlite_basic_handler;

    return NGX_OK;
}


static char *
ngx_http_auth_sqlite_basic(ngx_conf_t *cf, void *post, void *data)
{
    ngx_str_t  *realm = data;

    size_t   len;
    u_char  *basic, *p;

    if (ngx_strcmp(realm->data, "off") == 0) {
        ngx_str_set(realm, "");
        return NGX_CONF_OK;
    }

    len = sizeof("Basic realm=\"") - 1 + realm->len + 1;

    basic = ngx_pnalloc(cf->pool, len);
    if (basic == NULL) {
        return NGX_CONF_ERROR;
    }

    p = ngx_cpymem(basic, "Basic realm=\"", sizeof("Basic realm=\"") - 1);
    p = ngx_cpymem(p, realm->data, realm->len);
    *p = '"';

    realm->len = len;
    realm->data = basic;

    return NGX_CONF_OK;
}
