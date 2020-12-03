/**
 * 
 */
package in.co.rahogata.cryptokeep;

/**
 * @author shiva
 *
 */
public class DataCryptException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * 
     */
    public DataCryptException() {

    }

    /**
     * @param message
     */
    public DataCryptException(String message) {
        super(message);
    }

    /**
     * @param cause
     */
    public DataCryptException(Throwable cause) {
        super(cause);
    }

    /**
     * @param message
     * @param cause
     */
    public DataCryptException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * @param message
     * @param cause
     * @param enableSuppression
     * @param writableStackTrace
     */
    public DataCryptException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

}
