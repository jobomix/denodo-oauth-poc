package uk.gov.hmrc.oauth;


public class Main  {


    private String token;

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.err.println("the access token, the command to execute on denodo, and the truststore must be provided as parameters");
            System.exit(1);
        }
        String accessToken = args[0];
        String denodoCommand = args[1];
        String truststore = args[2];
        System.setProperty("javax.net.ssl.trustStore", truststore);
        DenodoRun connection = new DenodoRun(accessToken, denodoCommand);
        connection.connect();
    }

}
