import java.util.Date;
import java.text.SimpleDateFormat;

public class Logger{
	private boolean VERBOSE;
	
	public Logger(boolean verbose){
		VERBOSE = verbose;
	}
	
	private void log(String type, String msg){
		System.out.println("[" + type + "]" + " - " + new SimpleDateFormat("dd/MM/yyyy HH:mm:ss").format(new Date()) + ' ' + msg);
	}
	
	private void log(String type, String msg, Exception e){
		if (VERBOSE){
			System.out.println"[" + type + "]" + " - " + new SimpleDateFormat("dd/MM/yyyy HH:mm:ss").format(new Date()) + ' ' + msg);
			e.printStackTrace();
		} else {
			System.out.println("[" + type + "]" + " - " + new SimpleDateFormat("dd/MM/yyyy HH:mm:ss").format(new Date()) + ' ' + msg + "\nException: " + e.getMessage());
		}
	}
	
	public void error(String msg) {
        log("ERROR", msg);
    }
	
	public void error(String msg, Exception exception) {
        log("ERROR", msg, exception);
    }
	
	public void info(String msg){
		log("INFO", msg);
	}
	
	public void verbose(String msg){
		if (VERBOSE)
			log("VERB", msg);
	}
	
	public void warn(String msg){
		log("WARN", msg);
	}
	
	
	
	
}