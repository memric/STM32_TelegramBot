/*
 * telegram_bot.c
 *
 *  Created on: 26.08.2022
 *      Author: chudnikov
 */

#include "telegram_bot.h"
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "cJSON.h"

#include "mbedtls/net.h"
#include "mbedtls/platform.h"
#include "mbedtls/config.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/x509.h"

//#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

#define WEB_SERVER 			"api.telegram.org"
#define WEB_URL 			WEB_SERVER"/bot"
#ifndef BOT_TOKEN
#error "Telegram bot token must be provided"
#endif
#define SERVER_PORT         443

#define UPDATE_TIMEOUT		5

#define HTTP_METHOD_GET		"GET"
#define HTTP_METHOD_POST	"POST"

#define TRACE               printf

const char *DRBG_PERSONALIZED_STR = "Telegram Bot";
extern const char *telegram_cert_pem;

static TaskHandle_t telebot_task = NULL;
static QueueHandle_t msg_queue = NULL;
/**
 * The DRBG used throughout the TLS connectionc
 */
extern mbedtls_ctr_drbg_context ctr_drbg;
/**
 * Entropy context used to seed the DRBG to use in the TLS connection
 */
extern mbedtls_entropy_context entropy;
/**
 * The parsed chain of trusted CAs
 */
static mbedtls_x509_crt cacert;
/**
 * The TLS configuration in use
 */
extern mbedtls_ssl_config conf;
/**
 * THe TLS context
 */
extern mbedtls_ssl_context ssl;

char url[256];
char buf[1024];
char resp[512] = {0};
static uint32_t last_chat_id = 0;

static cJSON *mainMarkup = NULL;

static int32_t TeleBot_Http_Request(const char *http_mthd, const char *t_mthd,
		char *req, uint32_t req_len,
		char *resp, uint32_t resp_len);
static void TeleBot_Task(void *arg);
int32_t TeleBot_SendMessage(uint32_t chat_id, const char *msg, cJSON *markup);
void TeleBot_MessageCallback(uint32_t chat_id, const char *msg);
int configureTlsContexts(int *socket, const char *server_name);
int sslVerify(void *ctx, mbedtls_x509_crt *crt, int depth, uint32_t *flags);
/**
 * @brief	Bot initialization
 *
 */
void TeleBot_Init(void)
{
	if (xTaskCreate(TeleBot_Task, "Telegram", 1024*4, NULL, 3, &telebot_task) != pdPASS)
	{
	    TRACE("Telegram bot task error\r\n");
	}
}

/**
 * @brief 	Connects to Telegram bot server, sends http request and
 * 			gets response
 *
 * @param http_mthd	HTTP method GET or POST
 * @param t_mthd	Telegram method
 * @param req		Request string (JSON)
 * @param req_len	Request length
 * @param resp		Pointer to buffer for response from server
 * @param resp_len	Response lengthp
 * @return
 */
static int32_t TeleBot_Http_Request(const char *http_mthd, const char *t_mthd,
		char *req, uint32_t req_len,
		char *resp, uint32_t resp_len)
{
	int32_t ret, len = -1;
	int32_t http_req_len = 0;
    int32_t ret_len = 0;

    /* Connect */
    int socket;
    if ((ret = mbedtls_net_connect((mbedtls_net_context *) &socket, WEB_SERVER, "443", MBEDTLS_NET_PROTO_TCP)) != 0)
    {
        mbedtls_printf("Low lewel connection failed. Ret: %"PRIi32"\r\n", ret);
    }
    else
    {
        if (configureTlsContexts(NULL, WEB_SERVER) != 0)
        {
            TRACE("SSL config failed.\r\n");
        }

        mbedtls_ssl_set_bio(&ssl, &socket, mbedtls_net_send, mbedtls_net_recv, NULL);

        /* Start the TLS handshake */
        mbedtls_printf("Starting the TLS handshake...\r\n");
        do {
            ret = mbedtls_ssl_handshake(&ssl);
        } while(ret != 0 &&
            (ret == MBEDTLS_ERR_SSL_WANT_READ ||
                ret == MBEDTLS_ERR_SSL_WANT_WRITE));
        if (ret < 0) {
            mbedtls_printf("mbedtls_ssl_handshake() returned -0x%04"PRIx32"\r\n", -ret);
            return ret;
        }
        mbedtls_printf("Successfully completed the TLS handshake\r\n");

        /*Compose request header*/
        len = snprintf(buf, sizeof(buf), "%s /bot%s/%s HTTP/1.1\r\n"
                       "Host: "WEB_SERVER"\r\n"
                       /*"User-Agent: esp-idf/1.0 esp32\r\n"*/
                       "Connection: close\r\n",
                       http_mthd, BOT_TOKEN, t_mthd);

        if (len > 0)
        {
            http_req_len += len;

            if ((req != NULL) && (req_len < (sizeof(buf) - http_req_len)))
            {
                /*Append request string*/
                len = snprintf(&buf[http_req_len], sizeof(buf) - len,
                               "Content-Type: application/json\r\n"
                               "Content-Length: %"PRIu32"\r\n\r\n", req_len);

                if (len > 0)
                {
                    http_req_len += len;

                    len = snprintf(&buf[http_req_len], sizeof(buf) - http_req_len, "%s", req);

                    if (len > 0) { http_req_len += len; }
                    else { http_req_len = 0; }
                }
                else
                {
                    http_req_len = 0;
                }
            }
            else
            {
                /*Append \r\n for GET request*/
                len = snprintf(&buf[http_req_len], sizeof(buf) - http_req_len, "\r\n");

                if (len > 0) { http_req_len += len; }
                else { http_req_len = 0; }
            }

            TRACE("HTTP Request: %s\r\n", buf);
        }

        if (http_req_len == 0)
        {
            TRACE("Request composing error\r\n");
        }
        else
        {
            size_t written_bytes = 0;

            /*write request*/
            do {
                ret = mbedtls_ssl_write(&ssl, (unsigned char *) buf + written_bytes, http_req_len - written_bytes);

                if (ret > 0)
                {
                    TRACE("%"PRIi32" bytes written\r\n", ret);
                    written_bytes += ret;
                }
                else
                {
                    TRACE("ssl write error\r\n");
                    break;
                }
            } while (written_bytes < http_req_len);

            //                /* Print information about the TLS connection */
            //                ret = mbedtls_x509_crt_info(buf, sizeof(buf),
            //                                            "\r  ", mbedtls_ssl_get_peer_cert(&ssl));
            //                if (ret < 0) {
            //                    mbedtls_printf("mbedtls_x509_crt_info() returned -0x%04X\r\n", -ret);
            //                    return ret;
            //                }
            //                mbedtls_printf("Server certificate:\n%s\n", buf);
            //
            //                /* Ensure certificate verification was successful */
            //                uint32_t flags = mbedtls_ssl_get_verify_result(&ssl);
            //                if (flags != 0) {
            //                    ret = mbedtls_x509_crt_verify_info(buf, sizeof(buf), "\r  ! ", flags);
            //                    if (ret < 0) {
            //                        mbedtls_printf("mbedtls_x509_crt_verify_info() returned "
            //                            "-0x%04X\r\n", -ret);
            //                        return ret;
            //                    } else {
            //                        mbedtls_printf("Certificate verification failed (flags %lu):"
            //                            "\r\n%s\r\n", flags, buf);
            //                        return -1;
            //                    }
            //                } else {
            //                    mbedtls_printf("Certificate verification passed\n");
            //                }

            mbedtls_printf("Established TLS connection to %s\r\n", WEB_SERVER);

            /*Read response*/
            if (written_bytes == http_req_len)
            {
                TRACE("Reading HTTP response...\r\n");

                do {
                    len = sizeof(buf);
                    memset(buf, 0, len);
                    ret = mbedtls_ssl_read(&ssl, (unsigned char *) buf, len);

                    if(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
                    {
                        continue;
                    }

                    if(ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
                    {
                        break;
                    }

                    if (ret < 0) {
                        TRACE("mbedtls_ssl_read returned [-0x%02"PRIx32"]\r\n", -ret);
                        break;
                    }

                    if (ret == 0) {
                        TRACE("\r\nEoF\r\n");
                        break;
                    }

                    len = ret;
                    TRACE("%"PRIi32" bytes read\r\n", len);
                    /* Print response directly to stdout as it is read */
                    for (int i = 0; i < len; i++) {
                        putchar(buf[i]);
                    }
                    putchar('\n'); // JSON output doesn't have a newline at end

                    /*JSON beginning searching*/
                    char *pch = strstr(buf, "\r\n{");
                    if (pch != NULL)
                    {
                        ret_len = 0;
                        len -= (pch - buf);
                    }
                    else
                    {
                        pch = buf;
                    }
                    /*Copy response*/
                    while ((len > 0) && (ret_len < resp_len))
                    {
                        *resp++ = *pch++;
                        ret_len++;
                        len--;
                    }

                } while (1);
            }
        }

        /* Close connection */
        mbedtls_ssl_close_notify(&ssl);

        mbedtls_net_free((mbedtls_net_context *) &socket);
        mbedtls_x509_crt_free( &cacert );
        mbedtls_ssl_free(&ssl);
        mbedtls_ssl_config_free(&conf);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
    }

    if (len < 0) ret_len = -1;

    return ret_len;
}

/**
 * getUpdates method
 */
static int32_t TeleBot_GetUpdates(int32_t *id)
{
	int32_t retval = -1;

	/*Construct JSON method object*/
	cJSON *message = cJSON_CreateObject();

	if (message != NULL)
	{
		cJSON *msg_timeout = cJSON_CreateNumber(UPDATE_TIMEOUT);
		cJSON *msg_offset = cJSON_CreateNumber(*id);

		if (msg_timeout != NULL && msg_offset != NULL)
		{
			cJSON_AddItemToObject(message, "timeout", msg_timeout);
			cJSON_AddItemToObject(message, "offset", msg_offset);

			char *req = cJSON_PrintUnformatted(message);

			retval = TeleBot_Http_Request("POST", "getUpdates", req, strlen(req), resp, sizeof(resp));

			if (retval > 0)
			{
				TRACE("Resp: %s", resp);

				cJSON *json = cJSON_ParseWithLength(resp, sizeof(resp));

				if (json != NULL)
				{
					cJSON *result = cJSON_GetObjectItemCaseSensitive(json, "result");
					cJSON *res_item;
					cJSON_ArrayForEach(res_item, result)
					{
						/*Get update id*/
						cJSON *upd_id = cJSON_GetObjectItemCaseSensitive(res_item, "update_id");
						if (upd_id != NULL && upd_id->valueint >= *id)
						{
							/*Recalculate offset*/
							*id = upd_id->valueint + 1;
						}

						cJSON *message = cJSON_GetObjectItemCaseSensitive(res_item, "message");
						cJSON *text = cJSON_GetObjectItemCaseSensitive(message, "text");

						if (text != NULL)
						{
							cJSON *chat = cJSON_GetObjectItemCaseSensitive(message, "chat");
							cJSON *chat_id = cJSON_GetObjectItemCaseSensitive(chat, "id");

							TeleBot_MessageCallback((uint32_t) chat_id->valueint, text->valuestring);
						}
					}

					cJSON_Delete(json);
				}
			}

			free(req);
		}

		cJSON_Delete(message);
	}

	return retval;
}

/**
 * Sends message
 */
int32_t TeleBot_SendMessage(uint32_t chat_id, const char *msg, cJSON *markup)
{
	int32_t retval = -1;

	/*Construct JSON method object*/
	cJSON *message = cJSON_CreateObjectReference(NULL);

	if (message != NULL)
	{
		cJSON *msg_chat_id = cJSON_CreateNumber(chat_id);
		cJSON *msg_text = cJSON_CreateString(msg);

		if (msg_chat_id != NULL && msg_text != NULL)
		{
			cJSON_AddItemToObject(message, "chat_id", msg_chat_id);
			cJSON_AddItemToObject(message, "text", msg_text);

			if (markup != NULL)
			{
				cJSON_AddItemToObject(message, "reply_markup", markup);
			}

			char *req = cJSON_PrintUnformatted(message);

			TRACE("sendMessage: %s", req);

			retval = TeleBot_Http_Request("POST", "sendMessage", req, strlen(req), resp, sizeof(resp));

			free(req);
		}

		cJSON_Delete(message);
	}

	return retval;
}

/**
 * @brief   Enqueue massage to send
 *
 * @param msg
 */
void TeleBot_MessagePush(const char *msg)
{
    if (msg_queue != NULL)
    {
        xQueueSend(msg_queue, &msg, 10);
    }
}

/**
 * Main task
 */
static void TeleBot_Task(void *arg)
{
	(void) arg;
	int32_t id = -1;
	int32_t resp_len;

	msg_queue = xQueueCreate(10, sizeof(const char *));

	/*Create markup*/
	mainMarkup = cJSON_CreateObject();

	if (mainMarkup != NULL)
	{
		cJSON *btn1 = cJSON_CreateString("Info");
		cJSON *btn2 = cJSON_CreateString("Sys Tick");

		cJSON *btns = cJSON_CreateArray();
		cJSON *row1 = cJSON_CreateArray();

		if (btn2 != NULL && btn1 != NULL &&
				btns != NULL && row1 != NULL)
		{
			cJSON_AddItemToArray(row1, btn1);
			cJSON_AddItemToArray(row1, btn2);
			cJSON_AddItemToArray(btns, row1);

			cJSON_AddItemToObject(mainMarkup, "keyboard", btns);
		}
	}

	while (1)
	{
		/*Get updates*/
		resp_len = TeleBot_GetUpdates(&id);

		if (resp_len > 0 && id != -1)
		{
			memset(resp, 0, resp_len);
		}

		/* Check messages to send */
		if (msg_queue != NULL)
		{
		    BaseType_t ret;

		    do
		    {
		        char *msg = NULL;

		        ret = xQueueReceive(msg_queue, &msg, 0);

		        if (msg != NULL && last_chat_id != 0)
		        {
		            TeleBot_SendMessage(last_chat_id, msg, mainMarkup);
		        }
		    }
		    while(ret == pdPASS);
		}

		vTaskDelay(1000 / portTICK_PERIOD_MS);
	}
}

/**
 * Message callback
 */
void TeleBot_MessageCallback(uint32_t chat_id, const char *msg)
{
    last_chat_id = chat_id;

    char resp_msg[128];

	TRACE("Message from %"PRIu32": %s", chat_id, msg);

	if (strcmp(msg, "Info") == 0)
	{
	    TeleBot_SendMessage(chat_id, "STM32 TelegramBot", mainMarkup);
	}
	else if (strcmp(msg, "Sys Tick") == 0)
	{
	    snprintf(resp_msg, sizeof(resp_msg), "Sys Tick: %"PRIu32"", xTaskGetTickCount());
	    TeleBot_SendMessage(chat_id, resp_msg, mainMarkup);
	}
	else
	{
	    TeleBot_SendMessage(chat_id, "Unknown message", mainMarkup);
	}
}

int configureTlsContexts(int *socket, const char *server_name)
{
    int ret;

    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_printf( "\n  . Seeding the random number generator..." );

    mbedtls_entropy_init( &entropy );

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
            (const unsigned char *) DRBG_PERSONALIZED_STR,
            strlen(DRBG_PERSONALIZED_STR) + 1);

    if (ret != 0) {
        TRACE("mbedtls_ctr_drbg_seed() returned -0x%04X\n", -ret);
        return ret;
    }

    ret = mbedtls_x509_crt_parse(&cacert,
                        (const unsigned char *) telegram_cert_pem,
                        strlen(telegram_cert_pem) + 1);
    if (ret != 0) {
        TRACE("mbedtls_x509_crt_parse() returned -0x%04X\n", -ret);
        return ret;
    }

    ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        TRACE("mbedtls_ssl_config_defaults() returned -0x%04X\n",
                       -ret);
        return ret;
    }

    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    /*
     * It is possible to disable authentication by passing
     * MBEDTLS_SSL_VERIFY_NONE in the call to mbedtls_ssl_conf_authmode()
     */
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);

    /* Configure certificate verification function to clear time/date flags */
    mbedtls_ssl_conf_verify(&conf, sslVerify, NULL);

#if HELLO_HTTPS_CLIENT_DEBUG_LEVEL > 0
    mbedtls_ssl_conf_dbg(&conf, sslDebug, NULL);
    mbedtls_debug_set_threshold(HELLO_HTTPS_CLIENT_DEBUG_LEVEL);
#endif /* HELLO_HTTPS_CLIENT_DEBUG_LEVEL > 0 */

    if ((ret = mbedtls_ssl_setup( &ssl, &conf)) != 0) {
        mbedtls_printf("mbedtls_ssl_setup() returned -0x%04X\n", -ret);
        return ret;
    }

    if ((ret = mbedtls_ssl_set_hostname( &ssl, server_name )) != 0) {
        mbedtls_printf("mbedtls_ssl_set_hostname() returned -0x%04X\n",
                       -ret);
        return ret;
    }

//    mbedtls_ssl_set_bio(&ssl, socket, sslSend, sslRecv, NULL);

    return 0;
}

int sslVerify(void *ctx, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
    int ret = 0;

    /*
     * If MBEDTLS_HAVE_TIME_DATE is defined, then the certificate date and time
     * validity checks will probably fail because this application does not set
     * up the clock correctly. We filter out date and time related failures
     * instead
     */
    *flags &= ~MBEDTLS_X509_BADCERT_FUTURE & ~MBEDTLS_X509_BADCERT_EXPIRED;

#if HELLO_HTTPS_CLIENT_DEBUG_LEVEL > 0
    HelloHttpsClient *client = static_cast<HelloHttpsClient *>(ctx);

    ret = mbedtls_x509_crt_info(client->gp_buf, sizeof(gp_buf), "\r  ", crt);
    if (ret < 0) {
        mbedtls_printf("mbedtls_x509_crt_info() returned -0x%04X\n", -ret);
    } else {
        ret = 0;
        mbedtls_printf("Verifying certificate at depth %d:\n%s\n",
                       depth, client->gp_buf);
    }
#endif /* HELLO_HTTPS_CLIENT_DEBUG_LEVEL > 0 */

    return ret;
}
