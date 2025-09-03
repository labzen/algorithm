/*

  Jacksum 3.2.0 - a checksum utility in Java
  Copyright (c) 2001-2022 Dipl.-Inf. (FH) Johann N. Löfflmann,
  All Rights Reserved, <https://jacksum.net>.

  This program is free software: you can redistribute it and/or modify it under
  the terms of the GNU General Public License as published by the Free Software
  Foundation, either version 3 of the License, or (at your option) any later
  version.

  This program is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
  FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
  details.

  You should have received a copy of the GNU General Public License along with
  this program. If not, see <https://www.gnu.org/licenses/>.

 */
package net.jacksum;

import net.jacksum.algorithms.AbstractChecksum;
import net.jacksum.selectors.Selector;
import net.jacksum.selectors.SelectorInterface;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import static net.jacksum.selectors.Selectors.allSelectorClasses;

/**
 * HashFunctionFactory
 */
public class HashFunctionFactory {

  private static final Map<String, Class<?>> cacheOfSelectorClasses = new HashMap<>();

  private static final boolean cacheOfSelectorClassesEnabled = true;

  /**
   * Get a hash function.
   *
   * @param algorithm the name of the algorithm.
   * @return an instance of an AbstractChecksum that matches the criteria
   * @throws NoSuchAlgorithmException if an algorithm with the criteria cannot be found
   */
  public static AbstractChecksum getHashFunction(String algorithm) throws NoSuchAlgorithmException {
    return getHashFunction(algorithm, false);
  }

  public static AbstractChecksum getHashFunction(String algorithm, boolean alternate) throws NoSuchAlgorithmException {

    // construct an array of classes so that we can iterate over it
    Class<?>[] arrayOfSelectorClasses;
    if (cacheOfSelectorClasses.containsKey(algorithm)) {
      arrayOfSelectorClasses = new Class[1];
      arrayOfSelectorClasses[0] = cacheOfSelectorClasses.get(algorithm);
    } else {
      arrayOfSelectorClasses = allSelectorClasses;
    }

    for (Class<?> selectorClass : arrayOfSelectorClasses) {
      try {
        Constructor<?> constructor = selectorClass.getConstructor();
        SelectorInterface selector = (Selector) constructor.newInstance();

        selector.setName(algorithm);
        //System.out.println(selector);

        if (selector.doesMatch(algorithm)) {
          AbstractChecksum checksum = selector.getImplementation(alternate);
          checksum.setActualAlternateImplementationUsed(selector.isActualAlternateImplementationUsed());
          checksum.setName(selector.getName());

          if (cacheOfSelectorClassesEnabled) {
            // fill the cache with the algorithm that we have just found
            // in order to save time the next time the same request comes along
            cacheOfSelectorClasses.put(selector.getName(), selectorClass);

            // and if the selector has aliases for us, put them to the cache as well
            Map<String, String> aliases = selector.getAvailableAliases();

            if (aliases != null) {
              for (String key : aliases.keySet()) {
                cacheOfSelectorClasses.put(key, selectorClass);
              }
            }
          }
          return checksum;
        }
      } catch (NoSuchMethodException | SecurityException | InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException ex) {
        Logger.getLogger(HashFunctionFactory.class.getName()).log(Level.SEVERE, null, ex);
      }
    }
    throw new NoSuchAlgorithmException(algorithm + " is an unknown algorithm.");

  }

}
