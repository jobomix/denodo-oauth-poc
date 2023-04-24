package uk.gov.hmrc.oauth;

import com.opencsv.CSVWriter;

import java.io.StringWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

import static com.opencsv.CSVWriter.DEFAULT_ESCAPE_CHARACTER;
import static com.opencsv.CSVWriter.DEFAULT_LINE_END;
import static com.opencsv.CSVWriter.DEFAULT_QUOTE_CHARACTER;
import static com.opencsv.CSVWriter.DEFAULT_SEPARATOR;

public class DenodoRun {


    private final String url;
    private final String denodoCommand;


    public DenodoRun(String accessToken, String denodoCommand) {
        this.url = "jdbc:vdb://denodo.positdev.co.uk:9999/oauth_db?useOAuth2=true&accessToken=" + accessToken;
        this.denodoCommand = denodoCommand;
    }


    public void connect() throws Exception {
        Class.forName("com.denodo.vdp.jdbc.Driver");
        DriverManager.registerDriver(new com.denodo.vdp.jdbc.Driver());

        Connection con = DriverManager.getConnection(url);

        Statement stmt = con.createStatement();

        ResultSet rs = stmt.executeQuery(denodoCommand);
        StringWriter sWriter = new StringWriter();

        CSVWriter writer = new CSVWriter(sWriter, DEFAULT_SEPARATOR, DEFAULT_QUOTE_CHARACTER, DEFAULT_ESCAPE_CHARACTER, DEFAULT_LINE_END);

        writer.writeAll(rs, true);

        writer.close();

        System.out.println(sWriter);
    }

}
