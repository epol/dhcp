from flask import Flask,render_template,abort

from vutuf_base import Server,Packet,session

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/server/')
def server_list():
    servers = session.query(Server).all()
    return render_template('server_list.html',servers=servers)

@app.route('/server/<serverip>')
def server(serverip):
    try:
        server = session.query(Server).filter(Server.ip==serverip).one()
    except:
        abort(404)
    else:
        packets = session.query(Packet).filter(Packet.server_id==server.id).order_by(Packet.date.desc()).all()
        return render_template('server.html',server=server,packets=packets)

@app.route('/packet/')
def packet_list():
    packets = session.query(Packet).order_by(Packet.date.desc()).all()
    return render_template('packet_list.html',packets=packets)

@app.route('/packet/<int:id>')
def packet(id):
    try:
        packet = session.query(Packet).filter(Packet.id==id).one()
    except:
        abort(404)
    else:
        return render_template('packet.html',packet=packet)

if __name__ == '__main__':
    app.debug = True
    app.run()
