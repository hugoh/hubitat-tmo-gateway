/**
 * Virtual button to reboot T-Mobile Internet Router
 *
 * Credits for the logic go to highvolt-dev: https://github.com/highvolt-dev/tmo-monitor
 */

import groovy.transform.Field

@Field static final String BOOL = 'bool'
@Field static final String ENUM = 'enum'
@Field static final String PASSWORD = 'password'
@Field static final String STRING = 'string'

@Field static final String ROUTER_NOKIA = 'Nokia'

metadata {
    definition(
            name: 'T-Mobile Internet Gateway Driver',
            namespace: 'hugoh',
            author: 'Hugo Haas',
            importUrl: 'https://raw.githubusercontent.com/hugoh/hubitat-tmo-gateway/release/tmo-gateway.groovy') {
        capability 'Actuator'

        command 'reboot'
            }

    preferences {
        input name: 'username', type: STRING, title: 'T-Mobile Gateway Username', required: true
        input name: 'password', type: PASSWORD, title: 'T-Mobile Gateway Password', required: true
        input name: 'IP', type: STRING, title: 'Router IP address', defaultValue: '192.168.12.1', required: true
        input name: 'Gateway', type: ENUM, title: 'Type of gateway',
            options: [ROUTER_NOKIA], defaultValue: ROUTER_NOKIA, required: true
        input name: 'dryRun', type: BOOL,
                    title: '[DRY-RUN] Only pretend to send commands; for debugging purposes', defaultValue: false
        input name: 'logEnable', type: BOOL, title: 'Enable debug logging', defaultValue: false
    }
}

void logDebug(String msg) {
    if (logEnable) {
        log.debug(msg)
    }
}

void login() {
    boolean success = false
    httpGet("http://${settings.IP}/login_web_app.cgi?nonce") { nonceResp ->
        if (nonceResp?.isSuccess()) {
            nonceJson = parseJson(nonceResp.getData().toString())
            logDebug("Got nonce JSON: ${nonceJson}")
            nonce = nonceJson.nonce
            logDebug("Got nonce: ${nonce}")
            passHashInput = settings.password.toLowerCase()
            userPassHash = sha256(settings.username, passHashInput)
            userPassNonceHash = sha256url(userPassHash, nonce)
            loginRequest = [
                    'uri' : "http://${settings.IP}/login_web_app.cgi",
                    'body': [
                            'userhash'     : sha256url(settings.username, nonce),
                            'RandomKeyhash': sha256url(nonceJson.randomKey, nonce),
                            'response'     : userPassNonceHash,
                            'nonce'        : base64urlEscape(nonce),
                            'enckey'       : random16bytes(),
                            'enciv'        : random16bytes()
                    ]
            ]
            logDebug("Login request: ${loginRequest}")
            httpPost(loginRequest) { loginResp ->
                if (loginResp?.isSuccess()) {
                    resp = loginResp.getData().toString()
                    logDebug("Login response: ${resp}")
                    loginJson = parseJson(resp)
                    state.sid = loginJson.sid
                    logDebug("Sid: ${state.sid}")
                    state.csrfToken = loginJson.token
                    logDebug("Token: ${state.csrfToken}")
                    success = true
                }
            }
        }
    }
    state.loginSuccessful = success
}

void reboot() {
    login()
    if (!state.loginSuccessful) {
        log.error('Cannot reboot without successful login flow')
        return
    }
    rebootRequest = [
            'uri' : "http://${settings.IP}/reboot_web_app.cgi",
            headers: [
                'Cookie': "sid=${state.sid}"
            ],
            'body': [
                    'csrf_token'     : state.csrfToken,
            ]
    ]
    logDebug("Reboot request: ${rebootRequest}")
    rebootMsg = 'T-Mobile Internet Router reboot successfully requested'
    if (!settings.dryRun) {
        httpPost(rebootRequest) { rebootResp ->
            resp = rebootResp.getData()
            if (rebootResp?.isSuccess()) {
                logDebug("Reboot response: ${resp}")
                log.info(rebootMsg)
            } else {
                log.error("Reboot request failed: ${resp}")
            }
        }
    } else {
        log.info("[DRY-RUN] ${rebootMsg} [/DRY-RUN]")
    }
}

String base64urlEscape(String b64) {
    String out = ''
    for (char c : b64.toCharArray()) {
        switch (c) {
            case '+':
                out += '-'
                break
            case '/':
                out += '_'
                break
            case '=':
                out += '.'
                break
            default:
                out += c
                break
        }
    }
    return out
}

String sha256(String val1, String val2) {
    hash = java.security.MessageDigest.getInstance('SHA-256')
    hash.update("${val1}:${val2}".getBytes('UTF-8'))
    return hash.digest().encodeBase64().toString()
}

String sha256url(String val1, String val2) {
    return base64urlEscape(sha256(val1, val2))
}

String random16bytes() {
    Random r = new Random() // groovylint-disable-line InsecureRandom
    byte[] bytes = new byte[16]
    r.nextBytes(bytes)
    return base64urlEscape(bytes.encodeBase64().toString())
}
