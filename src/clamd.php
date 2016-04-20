<?php

/* clamd.php v0.1 ClamAV daemon interface.
 *
 * Author  : Barakat S. <b4r4k47@hotmail.com>
 * Licence : MIT
 */

define('CLAMD_PIPE', '/var/run/clamav/clamd.ctl');
define('CLAMD_HOST', '127.0.0.1');
define('CLAMD_PORT', 3310);
define('CLAMD_MAXP', 20000);

/* EICAR is a simple test for AV scanners, see: https://en.wikipedia.org/wiki/EICAR_test_file */
$EICAR_TEST = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';


/* An abstract class that `ClamdPipe` and `ClamdNetwork` will inherit. */
abstract class ClamdBase {

    abstract protected function getSocket();

    /* Send command to Clamd */
    private function sendCommand($command) {
        $return = null;

        try {
            $socket = $this->getSocket();
        } catch (Exception $e) {
            return false;
        }

        socket_send($socket, $command, strlen($command), 0);
        socket_recv($socket, $return, CLAMD_MAXP, 0);
        socket_close($socket);

        return $return;
    }

    /* `ping` command is used to see whether Clamd is alive or not */
    public function ping() {
        $return = $this->sendCommand('PING');
        return strcmp($return, 'PONG') === 0 ? true : false;
    }

    /* `version` is used to receive the version of Clamd */
    public function version() {
        $result = $this->sendCommand('VERSION');
        return $result !== FALSE
            ? trim($result)
            : false;
    }

    /* `ready` is used to determine clamav is available, up and running */
    public function ready(){
        try {
            $this->getSocket();
        } catch (Exception $e) {
            return false;
        }

        if( $this->version() !== FALSE ){
            return true;
        }

        return false;
    }

    /* `reload` Reload Clamd */
    public function reload() {
        return $this->sendCommand('RELOAD');
    }

    /* `shutdown` Shutdown Clamd */
    public function shutdown() {
        return $this->sendCommand('SHUTDOWN');
    }

    /* `fileScan` is used to scan single file. */
    public function fileScan($file) {
        $result = $this->sendCommand('SCAN ' .  $file);
        if( $result === FALSE ){
            return false;
        }

        list($file, $stats) = explode(':', $result);
        return array( 'file' => $file, 'stats' => trim($stats));
    }

    /* `continueScan` is used to scan multiple file/directories.  */
    public function continueScan($file) {
        $return = array();

        $result = $this->sendCommand('CONTSCAN ' .  $file);
        if($result === FALSE){
            return false;
        }

        foreach( explode("\n", trim($result)) as $results ) {
            list($file, $stats) = explode(':', $results);
            array_push($return, array( 'file' => $file, 'stats' => trim($stats) ));
        }
        return $return;
    }

    /* `streamScan` is used to scan a buffer. */
    public function streamScan($buffer) {
        $port    = null;
        $socket  = null;
        $command = 'STREAM';
        $return  = null;

        try {
            $socket = $this->getSocket();
        } catch (Exception $e) {
            return false;
        }
        socket_send($socket, $command, strlen($command), 0);
        socket_recv($socket, $return, CLAMD_MAXP, 0);

        sscanf($return, 'PORT %d\n', $port);

        $stream = socket_create(AF_INET, SOCK_STREAM, 0);
        socket_connect($stream, CLAMD_HOST, $port);
        socket_send($stream, $buffer, strlen($buffer), 0);
        socket_close($stream);

        socket_recv($socket, $return, CLAMD_MAXP, 0);

        socket_close($socket);

        return array('stats' => trim(str_replace('stream: ', '', $return)));
    }

    /**
     * Checks whether the given file is infected
     * @param  pathString   $file           File to be checked
     * @param  boolean      $forceCheck     Determines if infected check can silently fail.
     *                                      e.g. when clamAV isn't available
     *                                      Changes return behaviour
     * @return boolean/Exceptions           returns true/false if $forceCheck is false (silent Fail)
     *                                      returns true/false/null if $forceCheck is true (default)
     */
    public function infected($file, $forceCheck = true){
        $fileScanResult = $this->fileScan( $file );
        if( $fileScanResult === FALSE && $forceCheck ){
            return null;
        }

        return $fileScanResult["stats"] === "OK";
    }

}

/* This class can be used to connect to local socket, the default */
class ClamdPipe extends ClamdBase {
    private $pip;

    /* You need to pass the path to the socket pipe */
    public function __construct($pip=CLAMD_PIPE) {
        $this->pip = $pip;
    }

    protected function getSocket() {
        $socket = socket_create(AF_UNIX, SOCK_STREAM, 0);

        if( !file_exists($this->pip) ){
            $errorcode = socket_last_error();
            $errormsg = socket_strerror($errorcode);
            throw new Exception("ClamAV: Socket doesn't exist. ("+$errorcode+")["+$errormsg+"]");
            return false;
        }

        if( !socket_connect($socket, $this->pip) ){
            $errorcode = socket_last_error();
            $errormsg = socket_strerror($errorcode);
            throw new Exception("ClamAV: Socket connection error. ("+$errorcode+")["+$errormsg+"]");
            return false;
        }

        return $socket;
    }
}


/* This class can be used to connect to Clamd running over the network */
class ClamdNetwork extends ClamdBase {
    private $host;
    private $port;

    /* You need to pass the host address and the port the the server */
    public function __construct($host=CLAMD_HOST, $port=CLAMD_PORT) {
        $this->host = $host;
        $this->port = $port;
    }

    protected function getSocket() {
        $socket = socket_create(AF_INET, SOCK_STREAM, 0);
        socket_connect($socket, $this->host, $this->port);
        return $socket;
    }
}

?>
