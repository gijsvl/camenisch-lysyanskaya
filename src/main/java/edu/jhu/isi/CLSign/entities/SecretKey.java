package edu.jhu.isi.CLSign.entities;

import it.unisa.dia.gas.plaf.jpbc.field.z.ZrElement;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class SecretKey {
    private ZrElement x;
    private ZrElement y;
    private List<ZrElement> z = new ArrayList<ZrElement>();

    public SecretKey(final ZrElement x, final ZrElement y, final ZrElement... z) {
        this.x = x;
        this.y = y;
        this.z = Arrays.asList(z);
    }

    public ZrElement getX() {
        return x;
    }

    public ZrElement getY() {
        return y;
    }

    public ZrElement getZ(final int index) {
        return z.get(index);
    }

    public List<ZrElement> getZ() {
        return z;
    }
}
