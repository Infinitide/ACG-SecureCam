import java.util.Date;
import java.text.SimpleDateFormat;

public class Logger{
	private boolean VERBOSE;
	
	/**
	 * Initliases Logger
	 * @param 	verbose	Determines amound of details printed
	 */
	public Logger(boolean verbose){
		VERBOSE = verbose;
	}
	
	/**
	 * Print out log message to stdout
	 * @param	type	Log message type
	 * @param	msg		Log message
	 */
	private void log(String type, String msg){
		System.out.println("[" + type + "]" + " - " + new SimpleDateFormat("dd/MM/yyyy HH:mm:ss").format(new Date()) + ' ' + msg);
	}
	
	/**
	 * Print log message to stdoud
	 * @param	type	Log message type
	 * @param	msg		Log message
	 * @param	e		Exception which occurred
	 */
	private void log(String type, String msg, Exception e){
		if (VERBOSE){
			System.out.println("[" + type + "]" + " - " + new SimpleDateFormat("dd/MM/yyyy HH:mm:ss").format(new Date()) + ' ' + msg);
			e.printStackTrace();
		} else {
			System.out.println("[" + type + "]" + " - " + new SimpleDateFormat("dd/MM/yyyy HH:mm:ss").format(new Date()) + ' ' + msg);
			System.out.println("[" + type + "]" + " - " + new SimpleDateFormat("dd/MM/yyyy HH:mm:ss").format(new Date()) + "Exception: " + e.getMessage());
		}
	}
	
	/**
	 * Prints error message
	 * @param	msg	Message to print
	 */
	public void error(String msg) {
        log("ERROR", msg);
    }
	
	public void error(String msg, Exception exception) {
        log("ERROR", msg, exception);
    }
	
	/**
	 * Prints error message
	 * @param	msg	Message to print
	 * @param	e	Exception which occured
	 */
	public void error(String msg, Exception e) {
        log("ERROR", msg, e);
    }
	
	/**
	 * Print Info message
	 * @param	msg	Message to print
	 */
	public void info(String msg){
		log("INFO", msg);
	}
	
	/**
	 * Print out verbose messages
	 * @param	msg	Message to print
	 */
	public void verbose(String msg){
		if (VERBOSE)
			log("VERB", msg);
	}
	
	/**
	 * Print out warning messages
	 * @param	msg	Message to print
	 */
	public void warn(String msg){
		log("WARN", msg);
	}
	
}