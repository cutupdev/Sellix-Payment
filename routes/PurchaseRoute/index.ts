import { Request, Response, Router } from "express";
import { check, validationResult } from "express-validator";
import axios from "axios";
import dotenv from "dotenv";
import { authMiddleware } from "../../middleware";
import ServiceModel from "../../model/ServiceModel";
import SubscriptionModel from "../../model/SubscriptionModel";
import PaymentModel from "../../model/PaymentModel";
import ApiKeyModel from "../../model/ApiKeyModel";
import UserModel from "../../model/UserModel";
import keyGen from "../../utils/keyGen";
import mongoose from "mongoose";

dotenv.config();

// Create a new instance of the Express Router
const PurchaseRouter = Router();

// @route    Post api/purchase/purchase
// @desc     Purchase a service
// @access   Private
PurchaseRouter.post(
    '/purchase',
    check("serviceId", "ServiceId is required").notEmpty(),
    check("duration", "Duration is required").notEmpty(),
    check("userId", "UserId is required").notEmpty(),
    check("renewal", "Renewal is required").notEmpty(),
    authMiddleware,
    async (req: Request, res: Response) => {
        try {
            
            } catch (error) {
                console.log('error calling sellix api ===> ', error);
                res.status(500).send({ error });
            }

        } catch (err) {
            console.log('error purchasing service ===> ', err);
            res.status(500).send({ err });
        }
    }
)

// @route    Post api/purchase/webhook
// @desc     Sellix hook url
// @access   Public
PurchaseRouter.post(
    "/webhook",
    async (req: Request, res: Response) => {
        

            try {
                await newPayment.save(); // Save the new payment
            } catch (error) {
                console.log('error saving newPayment data in 2 ===> ', error)
            }

            return res.status(200).json({ message: 'Subscription extended' });
        }
    }
)

export default PurchaseRouter;