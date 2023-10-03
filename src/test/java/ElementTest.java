import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement;
import it.unisa.dia.gas.plaf.jpbc.field.gt.GTFiniteElement;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeAPairing;
import org.junit.jupiter.api.Test;

public class ElementTest {
    @Test
    public void testElementType() {
        Pairing pairing = new TypeAPairing(new TypeACurveGenerator(162, 512).generate());

        Element e = pairing.getGT().newRandomElement();

        if (e instanceof CurveElement) {
            System.out.println("this is curve element.");
        }

        if (e instanceof GTFiniteElement) {
            System.out.println("this is GT element.");
        }
    }

    @Test
    public void myTest() {
        String str = "a|b";
        String[] split = str.split("|");
        System.out.println(split[0]);
    }
}
