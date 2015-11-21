package tlsv12.asn1;

import tlsv12.util.Arrays;
import tlsv12.util.Strings;

import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.SimpleTimeZone;

/**
- * UTC time object.
 * Internal facade of {@link ASN1UTCTime}.
 * <p>
 * This datatype is valid only from 1950-01-01 00:00:00 UTC until 2049-12-31 23:59:59 UTC.
 * <p>
 * <hr>
 * <p><b>X.690</b></p>
 * <p><b>11: Restrictions on BER employed by both CER and DER</b></p>
 * <p><b>11.8 UTCTime </b></p>
 * <b>11.8.1</b> The encoding shall terminate with "Z",
 * as described in the ITU-T X.680 | ISO/IEC 8824-1 clause on UTCTime.
 * <p>
 * <b>11.8.2</b> The seconds element shall always be present.
 * <p>
 * <b>11.8.3</b> Midnight (GMT) shall be represented in the form:
 * <blockquote>
 * "YYMMDD000000Z"
 * </blockquote>
 * where "YYMMDD" represents the day following the midnight in question.
 */
public class ASN1UTCTime
    extends ASN1Primitive
{
    private byte[]      time;

    

    

    

    

    

    ASN1UTCTime(
        byte[] time)
    {
        this.time = time;
    }

    boolean isConstructed()
    {
        return false;
    }

    int encodedLength()
    {
        int length = time.length;

        return 1 + StreamUtil.calculateBodyLength(length) + length;
    }

    void encode(
        ASN1OutputStream  out)
        throws IOException
    {
        out.write(BERTags.UTC_TIME);

        int length = time.length;

        out.writeLength(length);

        for (int i = 0; i != length; i++)
        {
            out.write((byte)time[i]);
        }
    }

    boolean asn1Equals(
        ASN1Primitive o)
    {
        if (!(o instanceof ASN1UTCTime))
        {
            return false;
        }

        return Arrays.areEqual(time, ((ASN1UTCTime)o).time);
    }

    public int hashCode()
    {
        return Arrays.hashCode(time);
    }

    public String toString()
    {
      return Strings.fromByteArray(time);
    }
}
