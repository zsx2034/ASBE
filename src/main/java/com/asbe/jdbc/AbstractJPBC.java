package com.asbe.jdbc;

import java.util.Arrays;
import java.util.Collection;

import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;


public abstract class AbstractJPBC {

	static {
        PairingFactory.getInstance().setReuseInstance(false);
    }
	
	public static Collection parameters() {
        Object[][] data = {
                {false, "it/unisa/dia/gas/plaf/jpbc/pairing/a/a_181_603.properties"},
                {false, "it/unisa/dia/gas/plaf/jpbc/pairing/a1/a1_3primes.properties"},
                {false, "it/unisa/dia/gas/plaf/jpbc/pairing/d/d_9563.properties"},
                {false, "it/unisa/dia/gas/plaf/jpbc/pairing/e/e.properties"},
                {false, "it/unisa/dia/gas/plaf/jpbc/pairing/f/f.properties"},
                {false, "it/unisa/dia/gas/plaf/jpbc/pairing/g/g149.properties"},
                {true, "it/unisa/dia/gas/plaf/jpbc/pairing/a/a_181_603.properties"},
                {true, "it/unisa/dia/gas/plaf/jpbc/pairing/a1/a1_3primes.properties"},
                {true, "it/unisa/dia/gas/plaf/jpbc/pairing/d/d_9563.properties"},
                {true, "it/unisa/dia/gas/plaf/jpbc/pairing/e/e.properties"},
                {true, "it/unisa/dia/gas/plaf/jpbc/pairing/f/f.properties"},
                {true, "it/unisa/dia/gas/plaf/jpbc/pairing/g/g149.properties"}
        };

        return Arrays.asList(data);
    }

	protected String curvePath;
    protected boolean usePBC;
    public Pairing pairing;


    public AbstractJPBC(boolean usePBC, String curvePath) {
        this.usePBC = usePBC;
        this.curvePath = curvePath;
    }
}
