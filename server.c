#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL -1

int OpenListener(int port) {
    int sd;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("Can't bind port");
        abort();
    }

    if (listen(sd, 10) != 0) {
        perror("Can't configure listening port");
        abort();
    }

    return sd;
}

SSL_CTX* InitServerCTX(void) {
    /* TODO:
    /* 1. Initialize SSL library (SSL_library_init, OpenSSL_add_all_algorithms, SSL_load_error_strings)
     */
	SSL_library_init();
	OpenSSL_add_all_algoritms();
	SSL_load_error_strings();

/* 2. Create a new TLS server context (TLS_server_method)
    */
	const SSL_METHOD *method=TLS_server_method();
	SSL_CTX *ctx = SSL_CTX_new(method);
	
	if(*ctx ==NULL){
	ERROR_print_errors_fp(stderr);
    abort();
	}

 /* 3. Load CA certificate for client verification
    */
	IF(SSL_CTX_load_verify_locations(ctx,"ca.crt",NULL)<=0){
	ERR_print_errors_fp(stderr);
	abort();
}

 /* 4. Configure SSL_CTX to require client certificate (mutual TLS)
     */
	SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
	RETURN ctx;  

 }

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile) {
  /* TODO:
     * 1. Load server certificate using SSL_CTX_use_certificate_file
*/
    if(SSL_CTX_use_certificate_file(ctx,CertFIle,NULL)<=0){
    ERR_print_errors_fp(stderr);
    abort();
}
/* 2. Load server private key using SSL_CTX_use_PrivateKey_file
 */
    if(SSL_CTX_use_PrivaeKey_file(ctx,KeyFIle,NULL)<=0){
    ERR_print_errors_fp(stderr);
    abort();
}
/* 3. Verify that private key matches certificate using SSL_CTX_check_private_key
     */
    if(SSL_CTX_CHECK_private_key(ctx)=false){
    ERR_print_errors_fp(stderr);
    abort();
}

void ShowCerts(SSL* ssl) {
    /* TODO:
     * 1. Get client certificate (if any) using SSL_get_peer_certificate
*/
	X509 *certificate = SSL_get_peer_certificate(ssl);
	if (certificate == NULL){
	printf("No certif");
	return;
}
    /* 2. Print Subject and Issuer names
     */

    X509_NAME *issuer = X509_get_issuer_name(clientCerts);
    X509_NAME *subject = X509_get_subject_name(clientCerts);

    char issuerBuffer[256];
    char subjectBuffer[256];

    X509_NAME_oneline(subject, subjectBuffer, sizeof(subjectBuffer));
    printf("Subject: %s\n", subjectBuffer);
    
    X509_NAME_oneline(issuer, issuerBuffer, sizeof(issuerBuffer));
    printf("Issuer: %s\n", issuerBuffer);

	
}

void Servlet(SSL* ssl) {
    char buf[1024] = {0};

    if (SSL_accept(ssl) == FAIL) {
        ERR_print_errors_fp(stderr);
        return;
    }

    ShowCerts(ssl);

    int bytes = SSL_read(ssl, buf, sizeof(buf));
    if (bytes <= 0) {
        SSL_free(ssl);
        return;
    }
    buf[bytes] = '\0';
    printf("Client message: %s\n", buf);

    /* TODO:
     * 1. Parse XML from client message to extract username and password
     * 2. Compare credentials to predefined values (e.g., "sousi"/"123")
     * 3. Send appropriate XML response back to client
     */

    SSL_read(ssl,buf, (int)sizeof(buf));
    

    int sd = SSL_get_fd(ssl);
    SSL_free(ssl);
    close(sd);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <port>\n", argv[0]);
        exit(0);
    }

    int port = atoi(argv[1]);
    SSL_CTX *ctx;

    /* TODO:
     * 1. Initialize SSL context using InitServerCTX
     * 2. Load server certificate and key using LoadCertificates
     */

    int server = OpenListener(port);

    while (1) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;

        int client = accept(server, (struct sockaddr*)&addr, &len);
        printf("Connection from %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

        /* TODO:
         * 1. Create new SSL object from ctx
         * 2. Set file descriptor for SSL using SSL_set_fd
         * 3. Call Servlet to handle the client
         */
    }

    close(server);
    SSL_CTX_free(ctx);
}
