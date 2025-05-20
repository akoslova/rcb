# RCB Mode: A slightly different approach to the SCB 

Inspired by the Secure Codebook (SCB) mode of operation, the **Randomised Codebook (RCB)** modifies the SCB slightly in order to achieve better security with neglible cost of less correctness. The SCB was described by ETH Zürich researcher Fabio Banfi in a paper appearing in [IACR Transactions on Symmetric Cryptology, Volume 2022, Issue 4](https://tosc.iacr.org/index.php/ToSC/article/view/9970), and it is the first length-preserving encryption scheme that does achieve semantic security while allowing for imperfect decryption. See also [Banfi's git repository](https://github.com/fbanfi90/scb). In the SCB, the parameter $\sigma$ sets the capacity of the counter that keeps track of repeating blocks. Now, when this counter is exceeded, the counter resets itself. The RCB does not reset the counter but instead, uses a random output value after the capacity of the counter has been reached. Thus, the RCB aimed at achieving higher correctness but trading off correctness even more. This code was written for a bachelor thesis as a practical part, demonstrating examples in how security and correctness in the SCB and RCB are affected and how they compare.

## SCB & RCB Parameters
As in the SCB, the RCB defines two parameters, $\sigma$ and $\tau$, and it requires $\sigma + \tau \leq n$. In the SCB, the parameter $\sigma$ affects security whereas the parammeter $\tau$ affects correctness. In the RCB, $\sigma$ is transferred from affecting security to affecting correctness. Thus, the RCB guarantees semantic security, regardless of the values of the parameters. In the theoritical analysis, an optimal theritical value for $\sigma$ was found that minimises the upper bound of the advantage of an adversary. This value is $\sigma =  \frac{n-\log\beta}{2}$. For $\tau$, a reasonable value would be $2\log \beta \ll \tau \leq \frac{n+\log\beta}{2}$ with $\beta$ being the total number of queries an adversary can make. If we use AES with a block size of $n=128$, the optimal theoritical value for $\sigma$ would be $\sigma = 48$. The value of $\tau$ could be for example $\tau = 32$ as this was this value guaranteed perfect correctness when using the image of Tux in the SCB. In reality, a smaller value for $\sigma$ can be chosen to guarantee perfect correctness. See the bachelor thesis for more clarification.

> **Note:** Since the files ecb.py, scb.py, and rcb.py only allows to instantiate $\sigma$ and $\tau$ as multiples of 8, the above parameters choice for running the scripts should be 6 for $\sigma$ and 4 for $\tau$. For rcb_cor_bits.py, one should use the actual value. Also note that throughout the files, $\tau$ was mispelled as tao. I apologise for the inconvenience.

## Code
The requirements file consists of a list of packages that are needed to execute the scripts.

To work with the packages, you have to install them. You can do this by using the command prompt or terminal.
<pre>pip install -r requirements.txt</pre>

Now, to run the code, you open a new terminal and enter the src folder (use `ls /src`). Then, you can execute the different files by using the following command:

<pre> python &lt;file&gt; &ltparameters&gt; </pre>

In each file, at the end, one can find the usage listed with each parameter needed. There are also examples. In summary, the usages of each file are the following:

| File  | Usage |
|-------|-----|
| ecb.py  | python ecb.py &lt;image_path&gt; [&lt;key&gt;] &lt;mode&gt;  |
| scb.py | python scb.py &lt;image_path&gt; [&lt;key&gt;] &lt;sigma&gt; &lt;tao&gt; &lt;mode&gt; |
| rcb.py | python rcb.py &lt;image_path&gt; [&lt;key&gt;] &lt;sigma&gt; &lt;tao&gt; &lt;mode&gt; |
| rcb_cor_bits.py | python rcb_cor_bits.py &lt;image_path&gt; [&lt;key&gt;] &lt;sigma&gt; &lt;tao&gt; |
| compare.py | python compare.py &lt;image_path_1&gt; &lt;image_path_2&gt; |

The options for input are explained below:

| Input  | Details |
|-------|-----|
| enc  | A &lt;mode&gt; that produces an encrypted image |
| encdec | A &lt;mode&gt; that produces an image that encrypts and decrypts the original image |
| &lt;sigma&gt; | For the scrips scb.py and rcb.py, $\sigma$ is divided by 8, and must be an integer between 1 and 16. For rcb_cor_bits.py, $\sigma$ can be an integer between 1 and 128. |
| &lt;tao&gt; | For the scrips scb.py and rcb.py, $\tau$ is divided by 8, and must be an integer between 1 and 16. For rcb_cor_bits.py, $\tau$ can be an integer between 1 and 128. |
| &lt;key&gt; | Optional input. Needs to be encoded to a 16 byte key. |

## Img Folder

The img folder is the place where the original images are stored and the produced images are saved to. 

## Tests Folder

The tests folder contains several tests written for the scripts. To run the tests, use the command:

<pre> pytest tests/ </pre>

## Notice
The code is provided without any warranty and has not been written with efficiency in mind.

> **Important:** Currently, scb.c uses the input key as both the block cipher key $K_1$ and the pad key $K_2$. This clearly should be avoided.
