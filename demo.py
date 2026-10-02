from fastapi import FastAPI, Response
app = FastAPI()
@app.get('/weak')
def weak(response: Response):
    response.set_cookie('session', 'demo-value')
    response.headers['Access-Control-Allow-Origin'] = '*'
    return {'demo': 'weak'}
@app.get('/hardened')
def hardened(response: Response):
    response.headers.update({'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'", 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer'})
    response.set_cookie('session', 'demo-value', secure=True, httponly=True, samesite='strict')
    return {'demo': 'hardened'}
