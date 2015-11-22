package tlsv12.math.field;

import java.math.BigInteger;

public interface FiniteField {
    BigInteger getCharacteristic();


    int getDimension();
}
